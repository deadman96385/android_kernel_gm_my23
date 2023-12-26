//
//  Copyright (C) 2017 QNX Software Systems
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
//
//  SW-COMPONENT:        : qvm-shmem kernel module
//  COPYRIGHT:    (c) 2021 Robert Bosch Engineering and Business Solution, Bangalore.
//              GM VCU project specific changes are made on top of the file shared by QNX,
//              hence copyright of Bosch is also added.
//  HISTORY:
//  | Date      | Modification               | Author
//  | 15.05.21  | Initial revision           | krs4cob & voa1kor
//
//

#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME , __func__
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/sched/signal.h>

//
// <guest_shm.h> holds the data structures associated with the guest
// shared memory device.
//
#include "guest_shm.h"

// This module must be GPL because it uses the following GPL-only interfaces:
//   class_destroy
//   class_for_each_device
//   device_create
//   device_destroy
//   platform_driver_register
//   platform_driver_unregister
//   platform_get_irq
//   platform_get_resource
// Those are only used in the code that handles memory-mapped devices (as opposed to
// PCI-attached), so on systems where the guest has access to a PCI bus, it is possible
// to only support attaching to a PCI device and avoid using GPL-only interfaces.
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Robert Bosch Engineering and Business Solution, Bangalore");
MODULE_DESCRIPTION("Driver for QNX Hypervisor's shmem device to remount Android FS via vendor.bosch.android.remounter daemon");
MODULE_VERSION("0.1");

#define INVALID_PADDR   (~(unsigned long long)0)

#define GUEST_INTR_STATUS_MASK  ((1u << GUEST_SHM_MAX_CLIENTS) - 1u)

// This is essentially the application protocol over the shmem device.
// The "Remount_Shmem" shared memory region is divided in chunks of equal size, one
// per connected client.  A client is expected to send an interrupt every time
// it writes to its chunk of the memory region.
#define BUFF_SIZE 0x1000

// The parameters are used to tell the driver where to find memory-mapped devices.
// They are not used to discover PCI-attached devices.
static unsigned factory_num = 0;
static unsigned long long factories[GUEST_SHM_CURRENT_SUPPORTED_CLIENTS];
module_param_array(factories, ullong, &factory_num, S_IRUGO);
MODULE_PARM_DESC(factories, "Factory addresses");

static unsigned interrupt_num = 0;
static int interrupt_lines[GUEST_SHM_CURRENT_SUPPORTED_CLIENTS];
module_param_array(interrupt_lines, int, &interrupt_num, S_IRUGO);
MODULE_PARM_DESC(interrupt_lines, "Interrupt lines");

static struct class * shmem_class;
struct device *dev;

// Allow the devices to be written to from a /dev node
// When the device is memory-mapped, those nodes will be created
// automatically, but when the device is PCI-attached, an mknod will
// be required.  Proper handling of /dev is beyond the scope of this example.
static int major;
static struct device * all_devs[GUEST_SHM_CURRENT_SUPPORTED_CLIENTS] = { NULL };

/// Internal driver data
struct shmem_data {
    volatile struct guest_shm_factory *factory;
    volatile struct guest_shm_control *ctrl;
    char *shmdata;
    char *mybuff;
    unsigned attach_list;
    atomic_t incoming;
    struct tasklet_struct tasklet;
    int irq;
};

struct task_struct *task = NULL;

/// Schedule a tasklet to handle an interrupt from the device.
/// shmem_data::incoming accumulates all bit that get set into
/// status over time, because it is possible this interrupt
/// handler will run more than once by the time the tasklet is
/// eventually scheduled.
static irqreturn_t
shmem_irq(int const irq, void * const arg)
{
    struct device * const dev = arg;
    struct shmem_data * const data = dev_get_drvdata(dev);
    unsigned status;
    unsigned attach_list;

    // shared memory notification
    //
    // The status field contains two pieces of information. The bottom
    // 16 bits holds a bitset of all the clients that have notified
    // you since the last time you read the status field. E.g. If
    // bit (1 << 3) is on in the status value, that means that the
    // client using connection index 3 has notified you. The top
    // 16 bits of the field is the bitset of active connections
    // for the region. E.g. if the status field has (1 << (16+0)) and
    // (1 << (16+1)) on, connection index 0 and 1 are in use.
    //

    status = data->ctrl->status;
    attach_list = status >> GUEST_SHM_MAX_CLIENTS;
    status &= GUEST_INTR_STATUS_MASK;
    if ((status == 0) && (attach_list == data->attach_list)) {
        // Not our interrupt
        return IRQ_NONE;
    }

    atomic_or((int)status, &data->incoming);
    tasklet_schedule(&data->tasklet);

    return IRQ_HANDLED;
}

/// Print information about a processed interrupt to dmesg.
static void
shmem_print_incoming(unsigned long arg)
{
    struct device * const dev = (void *)(uintptr_t)arg;
    struct shmem_data * const data = dev_get_drvdata(dev);
    unsigned incoming = (unsigned)atomic_xchg(&data->incoming, 0);
    unsigned i;

    // It is entirely possible a client has come and gone by the time this
    // tasklet runs, so the change might not be detected here.
    unsigned const attach_list = data->ctrl->status >> GUEST_SHM_MAX_CLIENTS;
    unsigned const attach_list_changes = attach_list ^ data->attach_list;

    pr_info("Notification from QNX to Android \n");

    for (i = 0; i < GUEST_SHM_CURRENT_SUPPORTED_CLIENTS; ++i) {
        if (attach_list_changes & (1u << i)) {
            dev_info(dev, "client %2u %stached", i, (attach_list & (1u << i)) ? "at" : "de");
        }
        if (incoming & (1u << i)) {
            dev_info(dev, "connection %2u sent '%s'", i, &data->shmdata[i*BUFF_SIZE]);

            if (strncmp (&data->shmdata[i*BUFF_SIZE],MSG_FROM_QNX,strlen(MSG_FROM_QNX))== 0){
                if (NULL != task){
                    struct kernel_siginfo info = {0};
                    info.si_signo = SIGUSR1;
                    info.si_errno = 0;
                    info.si_code = SI_USER;
                    info.si_pid = task->tgid;
                    send_sig_info(SIGUSR1, &info,task);
                    pr_info("Notification from kernel module to remounter daemon \n");
                }
            }
        }
    }
    data->attach_list = attach_list;
}

/// Probe a device, independently of how it was discovered.
static int
shmem_probe(struct device * const dev, volatile struct guest_shm_factory * const factory, int irq)
{
    uint64_t paddr;
    struct shmem_data *data;
    int ret;
    unsigned i;

    data = kzalloc(sizeof(*data), GFP_KERNEL);
    if (data == NULL) {
        dev_err(dev, "no memory for shmem_data");
        return -ENOMEM;
    }
    data->factory = factory;

    if (factory->signature != GUEST_SHM_SIGNATURE) {
        kfree(data);
        dev_err(dev, "Signature incorrect. %llx != %llx",
            (unsigned long long)GUEST_SHM_SIGNATURE, (unsigned long long) factory->signature);
        return -ENXIO;
    }

    if (irq == -1) {
        irq = factory->vector;
    }
    dev_info(dev, "interrupt vector %d", irq);

    //
    // Set the name field on the factory page to identify the shared memory
    // region that you want to create/attach to.
    //
    strncpy((char *)factory->name, SHMEM_NAME,strlen(SHMEM_NAME));
    dev_info(dev, "about to create object '%s'", factory->name);

    //
    // Set the size field to indicate the number of 4K pages you want allocated
    // for the shared memory region. The act of writing this field causes the
    // hypervisor to create the shared memory region (or attach to it if it
    // already exists), so it must be done after the name has been set.
    // Although not technically required, this should be done using the
    // inline function guest_shm_create() since it has GCC directives to
    // prevent the compiler from re-ordering other factory page accesses
    // before/after the creation request.
    //
    guest_shm_create(factory, GUEST_SHM_CURRENT_SUPPORTED_CLIENTS);

    //
    // After the size has been set, we need to check the status field to
    // see if we successfully created/attached to the region.
    //
    if (factory->status != GSS_OK) {
        kfree(data);
        dev_err(dev, "creating failed: %d", factory->status);
        return -factory->status;
    }

    //
    // If we successfully created/attached to the region, the 'shmem' field
    // holds the physical address used to access the memory.
    //
    // NOTE: The first client that attempts to create the shared memory name
    // gets to choose the actual size of the shared memory region. Since you
    // can't tell if you were the first or not, you need to check the 'size'
    // field after the creation - it will have the actual number of pages
    // of the region. This may be larger, smaller, or the same size as what
    // you requested.
    //
    paddr = factory->shmem;
    dev_info(dev, "creation size %x, paddr=%llx", factory->size, (unsigned long long)paddr);

    //
    // Now we get a virtual address to reference the region. The returned
    // paddr is actually the 'control' page. It's used to receive notifications
    // that another connection has 'poked' the region (made some change that
    // you need to be aware of) or to 'poke' other connections when you make a
    // change. The physical pages following are the actual shared memory.
    // Control page is same as kernel page size.
    data->ctrl = memremap(paddr, (factory->size + 1) * KERNEL_PAGE_SIZE, MEMREMAP_WB);

    //
    // Each client that connects to shared memory region gets a unique
    // connection index number (0 through 15). This index is to form various
    // bitsets. The ctrl->idx field tells you what your connection index
    // number is.
    //
    dev_info(dev, "shared memory index %u", data->ctrl->idx);

    data->shmdata = (char *)data->ctrl + 0x1000u;
    data->mybuff = &data->shmdata[data->ctrl->idx * BUFF_SIZE];
    data->attach_list = data->ctrl->status >> GUEST_SHM_MAX_CLIENTS;

    data->tasklet = (struct tasklet_struct) {
        NULL, 0, ATOMIC_INIT(0), shmem_print_incoming, (unsigned long)(uintptr_t)dev };

    dev_set_drvdata(dev, data);

    //
    // Every time the ctrl->status field changes value, an
    // interrupt will be delivered to the guest.
    //
    ret = request_irq(irq, shmem_irq, IRQF_SHARED, SHMEM_IRQ, dev);
    if (ret < 0) {
        dev_err(dev,"irq request failed");
        memunmap((void *)data->ctrl);
        kfree(data);
        return ret;
    }
    data->irq = irq;

    for (i = 0; i < GUEST_SHM_CURRENT_SUPPORTED_CLIENTS; ++i) {
        if (all_devs[i] == NULL) {
            all_devs[i] = dev;
            break;
        }
    }
    dev->devt = MKDEV(major, i);

    return 0;
}

/// Perform the attachment-independent steps of detaching a device
static void
shmem_remove(struct device * const dev)
{
    struct shmem_data * const data = dev_get_drvdata(dev);
    unsigned minor = MINOR(dev->devt);

    if (minor < GUEST_SHM_CURRENT_SUPPORTED_CLIENTS) {
        all_devs[minor] = NULL;
    }

    free_irq(data->irq, dev);
    //
    // A write of any value to the detach field cleanly disconnects from
    // the shared memory region. All other clients will be notified and
    // the physical address range for the control and data fields in this
    // client will no longer be accessable.
    //
    data->ctrl->detach = 0;
    memunmap((void *)data->ctrl);
    kfree(data);
}

// Platform code

static int shmem_platform_probe(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    int irq = platform_get_irq(pdev, 0);
    struct resource *mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    void *fact;
    int ret;

    if (irq < 0 || mem == NULL) {
        dev_err(dev, "Unable to get resources\n");
        return -EINVAL;
    }

    fact = memremap(mem->start, mem->end - mem->start + 1, MEMREMAP_WB);
    if (fact == NULL) {
        dev_err(dev, "Unable to remap address %llx", mem->start);
        return -ENOMEM;
    }

    ret = shmem_probe(dev, fact, irq);
    if (ret < 0) {
        memunmap(fact);
        return ret;
    }

    return 0;
}

static const struct of_device_id shmem_of_match[] = {
    { .compatible = "qvm,guest_shm_remounter" },
    {}
};

static struct platform_driver shmem_pdriver = {
    .probe      = shmem_platform_probe,
    .driver     = {
        .name   = "qnx-shmem",
        .of_match_table = shmem_of_match,
    },
};

/// Detach from a memory-mapped device
static int
shmem_factory_remove(struct device * const dev, void * const arg)
{
    struct shmem_data * const data = dev_get_drvdata(dev);
    void *fact = (void *)data->factory;
    shmem_remove(dev);
    memunmap(fact);
    device_destroy(shmem_class, dev->devt);
    return 0;
}

/// Link a file descriptor with a device
static int
shmem_open(struct inode * const inode, struct file * const filp)
{
    struct device *dev;
    unsigned const minor = MINOR(inode->i_rdev);
    if (minor >= GUEST_SHM_CURRENT_SUPPORTED_CLIENTS)
    {
        pr_err("minor:%d greater than supported client:%d\n",minor,GUEST_SHM_CURRENT_SUPPORTED_CLIENTS);
        return -ENXIO;
    }
    dev = all_devs[minor];
    if (dev == NULL)
    {
        pr_err("device structure for minor:%d NULL\n",minor);
        return -ENXIO;
    }

    filp->private_data = dev;
    nonseekable_open(inode, filp);

    //Get the calling process details which is needed for sending the SIGUSR signal
    task = current;

    pr_info("The calling process is \"%s\" (pid %i)\n",
                current->comm, current->pid);

    return 0;
}

/// Handle a write on the character device
static ssize_t
shmem_write(struct file * const filp, const char __user * const buf, size_t const count,
    loff_t * const f_pos)
{
    struct device * const dev = filp->private_data;
    struct shmem_data * const data = dev_get_drvdata(dev);
    size_t const buflen = (count >= BUFF_SIZE) ? (BUFF_SIZE-1) : count;
    unsigned long const n = copy_from_user(data->mybuff, buf, buflen);
    data->mybuff[buflen-n] = 0;

    //
    // The value written to the notify field is a bitset that
    // tells which other clients should be informed that something
    // has happened and they should look at the shared memory region.
    // E.g. if you want to notify the client whose index is 2, you
    // should turn on (1 << 2) in the bitset.
    // The value ~0 is specially handled to mean "everybody but me".
    //
    data->ctrl->notify = ~0;

    pr_info("qvm-shmem:Notification from Android to QNX \n");

    return (ssize_t)buflen;
}
#if 0
static const struct pci_device_id shmem_pci_id[] = {
    { PCI_DEVICE(PCI_VID_BlackBerry_QNX, PCI_DID_QNX_GUEST_SHM), 0 },
    { 0 }
};

static struct pci_driver shmem_pci_driver = {
    .name = KBUILD_MODNAME,
    .id_table = shmem_pci_id,
    .probe = shmem_pci_probe,
    .remove = shmem_pci_remove,
};
#endif
static const struct file_operations shmem_fops = {
    .owner  =   THIS_MODULE,
    .write  =   shmem_write,
    .open   =   shmem_open,
    .llseek =   no_llseek
};

static int __init
shmem_init(void)
{
    unsigned i;
    unsigned found = 0;

    major = register_chrdev(0, CHAR_DEVICE_NAME, &shmem_fops);
    if (major < 0) {
        pr_err("char device %s failed",CHAR_DEVICE_NAME);
        return major;
    }

    if (factory_num == 0) {
        int ret;

        ret = platform_driver_register(&shmem_pdriver);
        if (ret)
        {
            unregister_chrdev(major,CHAR_DEVICE_NAME);
            return ret;
        }

    shmem_class = class_create (THIS_MODULE,CLASS_NAME);
    if (shmem_class == NULL)
    {
        pr_err("Class create failed");
        platform_driver_unregister(&shmem_pdriver);
        unregister_chrdev(major,CHAR_DEVICE_NAME);
        return -ENOMEM;
    }
    dev = device_create(shmem_class, NULL, MKDEV(major, 0), NULL, CHAR_DEVICE_NAME);
    if (dev == NULL) {
            pr_err("failed to create device");
            class_destroy(shmem_class);
            platform_driver_unregister(&shmem_pdriver);
            unregister_chrdev(major,CHAR_DEVICE_NAME);
            return -1;
        }
    return 0;
}

    shmem_class = class_create (THIS_MODULE, CLASS_NAME);
    if (shmem_class == NULL)
        return -ENOMEM;

    for (i = 0; i < factory_num; ++i) {
        struct device *dev;
        int irq;

        // The factory page size is same as kernel page size(4KB), hence entire page is mapped
        void * const fact = memremap(factories[i], KERNEL_PAGE_SIZE, MEMREMAP_WB);
        if (fact == NULL) {
            pr_err("invalid factory address %llx", factories[i]);
            continue;
        }
        // Since this module has only one minor device, minor num is not made part of device name
        dev = device_create(shmem_class, NULL, MKDEV(major, i), NULL, CHAR_DEVICE_NAME);
        if (dev == NULL) {
            pr_err("failed to create device for address %llx", factories[i]);
            class_destroy(shmem_class);
            break;
        }
        found = 1;

        if (i < interrupt_num) {
            irq = interrupt_lines[i];
        } else {
            irq = -1;
        }
        if (shmem_probe(dev, fact, irq) < 0) {
            device_destroy(shmem_class, dev->devt);
            class_destroy(shmem_class);
            pr_err("shmem_probe failed");
            break;
        }
    }
    return found ? 0 : -ENXIO;
}


static void __exit
shmem_exit(void){
    if (factory_num == 0) {
        device_destroy(shmem_class, dev->devt);
        class_destroy(shmem_class);
        platform_driver_unregister(&shmem_pdriver);
        //pci_unregister_driver(&shmem_pci_driver);
    }
    else {
        class_for_each_device(shmem_class, NULL, NULL, shmem_factory_remove);
        class_destroy(shmem_class);
    }
    unregister_chrdev(major, CHAR_DEVICE_NAME);
    pr_info("Module exiting..");
}

module_init(shmem_init);
module_exit(shmem_exit);
