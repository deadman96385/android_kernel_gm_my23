/*
 * dabridge.c
 *
 * USB Driver for the Delphi's Dual Role USB Bridge/Hub.
 * Any single port on a single hub can be enabled for
 * bridge mode (device role).
 *
 *  Copyright (c) 2015, Delphi Automotive PLC
 *  Created on: Jan 16, 2015
 *      Author: Sam Yeda <sam.yeda@delphi.com>
 *
 *  Revision History
 *  Sam Yeda        26OCT2015,  Beta release.
 *  Sam Yeda        14JAN2016,  Reset H2H USB device endpoints
 *                              when flushing H2H device endpoint fifo.
 *  Sam Yeda        13JUN2016,  Add Delphi VID/PID.
 *  Sam Yeda        02MAY2017,  Fix warning: assignment from incompatible pointer type
 *  Sam Yeda        21MAY2017,  Change the array length of struct dabridge_ep_name*
 *                              to actual length.
 *  Sam Yeda        13OCT2017,  Toggle port power if the bridge device is reset
 *                              while the port was in bridge mode. This will force
 *                              the downstream device to switch back to Host mode.
 *  Sam Yeda        15Nov2017,  xHCI driver does not support endpoint reset.
 *                              To work around this, re-set the H2H interface to trigger
 *                              drop and add endpoint which in turn resets the endpoints.
 *  Sam Yeda        14May2018,  Replace DRIVER_ATTR with DRIVER_ATTR_RW to allow
 *                              compatibility with newer Kernel version(s).
 *  Sam Yeda        30JUN2018,  Fix warning: "transfer buffer is on stack" for kernel >= 4.9
 *  Sam Yeda        15DEC2018,  Fix printed version number format.
 *  Sam Yeda        15DEC2018,  Use new API for PIVI HILN HUB.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*#define DEBUG*/
/*#define VERBOSE_DEBUG*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/usb.h>
#include <linux/usb/gadget.h>
#include <linux/usb/hcd.h>
#include <linux/kthread.h>
#include <linux/version.h>	/* for KERNEL_VERSION MACRO	*/

#include <asm/byteorder.h>
#include "dabridge.h"

static const char dabridge_driver_name[] = "dabridge";

static const char dabr_ep0name[] = "ep0";
/*
 * Gadget (Visible to B-Host) endpoint names for ep_autoconfig
 * The order of names is important for usb_ep_autoconfig matching
 */
static const char *const dabridge_ep_name[] = {
	dabr_ep0name, /* everyone has ep0 */
	"ep1in-bulk", "ep2out-bulk",
	"ep5in-int", "ep8out-iso",
	"ep3in-bulk", "ep4out-bulk",

	/* Fake endpoint(s) to satisfy test gadget drivers */
	"ep3in-iso", /* Gadget Zero */
};
static const char *const dabridge_ep_name_alt[] = {
	dabr_ep0name, /* everyone has ep0 */
	"ep1in-bulk", "ep2out-bulk",
	"ep5in-int", "ep6out-iso",
	"ep3in-bulk", "ep4out-bulk",

	/* Fake endpoint(s) to satisfy test gadget drivers */
	"ep3in-iso", /* Gadget Zero */
};
static const char *const dabridge_ep_name_no_isoc[] = {
	dabr_ep0name, /* everyone has ep0 */
	"ep1in-bulk", "ep2out-bulk",
	"ep5in-int",
	"ep3in-bulk", "ep4out-bulk",
};
static const char *const dabridge_ep_name_full_isoc[] = {
	dabr_ep0name, /* everyone has ep0 */
	"ep1in-bulk", "ep2out-bulk",
	"ep5in-int", "ep8out-iso",
	"ep3in-bulk", "ep4out-bulk",
	"ep7in-iso",
};

static const struct dabridge_info hiln_100_info = {
	.ep_names = (const char **)dabridge_ep_name,
	.num_of_ep_names = ARRAY_SIZE(dabridge_ep_name),
	.isoc_in_ep = 0,
	.isoc_out_ep = 0,
	.port_num_offset = 0,
	.port_switch_wait = 1,
	.new_apis = 0,
};
static const struct dabridge_info asic_101_info = {
	.ep_names = (const char **)dabridge_ep_name_alt,
	.num_of_ep_names = ARRAY_SIZE(dabridge_ep_name_alt),
	.isoc_in_ep = 0x87,
	.isoc_out_ep = 0x06,
	.port_num_offset = -1,
	.port_switch_wait = 100,
	.new_apis = 1,
};
static const struct dabridge_info asic_102_info = {
	.ep_names = (const char **)dabridge_ep_name,
	.num_of_ep_names = ARRAY_SIZE(dabridge_ep_name),
	.isoc_in_ep = 0,
	.isoc_out_ep = 0,
	.port_num_offset = -1,
	.port_switch_wait = 100,
	.new_apis = 1,
};
static const struct dabridge_info hiln_104_info = {
	.ep_names = (const char **)dabridge_ep_name_full_isoc,
	.num_of_ep_names = ARRAY_SIZE(dabridge_ep_name_full_isoc),
	.isoc_in_ep = 0,
	.isoc_out_ep = 0,
	.port_num_offset = 0,
	.port_switch_wait = 1,
	.new_apis = 0,
};
static const struct dabridge_info hiln_104_pivi_info = {
	.ep_names = (const char **)dabridge_ep_name_full_isoc,
	.num_of_ep_names = ARRAY_SIZE(dabridge_ep_name_full_isoc),
	.isoc_in_ep = 0,
	.isoc_out_ep = 0,
	.port_num_offset = 0,
	.port_switch_wait = 100,
	.new_apis = 1,
};
static const struct dabridge_info asic_105_info = {
	.ep_names = (const char **)dabridge_ep_name_no_isoc,
	.num_of_ep_names = ARRAY_SIZE(dabridge_ep_name_no_isoc),
	.isoc_in_ep = 0,
	.isoc_out_ep = 0,
	.port_num_offset = -1,
	.port_switch_wait = 100,
	.new_apis = 1,
};

/* Table of USB devices that work with this driver */
static const struct usb_device_id dabridge_usb_table[] = {
	{ USB_DEVICE(USB_UNWIRED_VENDOR_ID, USB_HILN_100_PRODUCT_ID),
		.driver_info = (unsigned long)&hiln_100_info, },
	{ USB_DEVICE(USB_UNWIRED_VENDOR_ID, USB_ASIC_101_PRODUCT_ID),
		.driver_info = (unsigned long)&asic_101_info, },
	{ USB_DEVICE(USB_UNWIRED_VENDOR_ID, USB_ASIC_102_PRODUCT_ID),
		.driver_info = (unsigned long)&asic_102_info, },
	{ USB_DEVICE_VER(USB_UNWIRED_VENDOR_ID, USB_HILN_104_PRODUCT_ID, 0x1700, 0x9900),
		.driver_info = (unsigned long)&hiln_104_pivi_info, }, /* *MUST* be above legacy */
	{ USB_DEVICE(USB_UNWIRED_VENDOR_ID, USB_HILN_104_PRODUCT_ID),
		.driver_info = (unsigned long)&hiln_104_info, },      /* Legacy */
	{ USB_DEVICE(USB_UNWIRED_VENDOR_ID, USB_ASIC_105_PRODUCT_ID),
		.driver_info = (unsigned long)&asic_105_info, },
	{ USB_DEVICE(USB_DELPHI_VENDOR_ID,  USB_ASIC_105_PRODUCT_ID),
		.driver_info = (unsigned long)&asic_105_info, },

	{ USB_DEVICE(0x1772, 0x0002),
		.driver_info = (unsigned long)&hiln_104_info, },
	{ } /* Terminating entry */
};
MODULE_DEVICE_TABLE(usb, dabridge_usb_table);

MODULE_DESCRIPTION (H2H_DRIVER_DESC);
MODULE_AUTHOR  ("Sam Yeda <sam.yeda@delphi.com>");
MODULE_AUTHOR  ("Copyright (C) 2015-2017, Delphi Automotive PLC");
MODULE_VERSION (H2H_DRIVER_VERSION);
MODULE_LICENSE ("GPL");

/*
typedef struct {
	u8 bridge;
	u8 gadget;
} ep_mapping_t;
static ep_mapping_t ep_mapping[] = {
	{0x81, 0x02},
	{0x02, 0x81},
	{0x83, 0x04},
	{0x04, 0x83},
	{0x85, 0x06},
	{0x06, 0x85},
	{0x87, 0x08},
	{0x08, 0x87},
};
*/

static DEFINE_MUTEX(device_list_lock);
static LIST_HEAD(dabridge_device_list);

static uint dabridge_device_count = 0;
static struct usb_driver dabridge_driver;
static char active_bridgeport[20] = "";
static struct dabridge_usb *active_bridgedev = NULL;

static int dabridge_port_select(struct dabridge_usb *dev, int portId);
static void dabridge_device_delete(struct kref *kref);
static int dabridge_epflush_fifo(struct dabridge_usb *dev, u16 ep_bits);
static int dabridge_port_power(struct dabridge_usb *dev, u8 port, u8 power);
static int dabridge_port_role_reverse(struct dabridge_usb *brdev, int portnum);
static inline bool dabridge_is_h2h_hub(struct usb_device *hdev, int busnum,
		int devnum);

/*-------------------------------------------------------------------------*/

/*
 * Kbuild is not very cooperative with respect to linking separately
 * compiled library objects into one module.  So for now we won't use
 * separate compilation ... ensuring init/exit sections work to shrink
 * the runtime footprint, and giving us at least some parts of what
 * a "gcc --combine ... part1.c part2.c part3.c ... " build would.
 */
#include "dabr_udc.c"

/*-------------------------------------------------------------------------*/

static void dabridge_device_delete(struct kref *kref)
{
	struct dabridge_usb *dev = kref_to_dabridge_usb(kref);

	if(active_bridgedev == dev) {
		active_bridgedev = NULL;
	}

	/*decrements the reference count of the usb device*/
	usb_put_dev(dev->usbdev);

	pr_info("%s deleted\n", dev->name);
	kfree(dev);
}

/*
 * If successful, it returns the number of bytes transferred, otherwise a
 * negative error number.
 */
static int dabridge_blocking_ctrl_rw(struct dabridge_usb *dev, bool isRead,
		struct usb_ctrlrequest *cmd, void *data)
{

	int rv;
	unsigned int iopipe;

	if (isRead) {
		iopipe = usb_rcvctrlpipe(dev->usbdev, 0);
	} else {
		iopipe = usb_sndctrlpipe(dev->usbdev, 0);
	}
	rv = usb_control_msg(dev->usbdev,
			iopipe,
			cmd->bRequest,
			cmd->bRequestType,
			cmd->wValue,
			cmd->wIndex,
			data,
			cmd->wLength,
			CTRL_MSG_TIMEOUT);
	return rv;

}

static void dabridge_print_hub_info(struct dabridge_usb *dev)
{
	int portn;
	struct usb_device *compdev = NULL;

	/* Find the composite device that holds the product firmware revision */
	usb_hub_for_each_child(dev->usbdev->parent, portn, compdev) {
		if ((le16_to_cpu(compdev->descriptor.idVendor) == USB_UNWIRED_VENDOR_ID ||
			le16_to_cpu(compdev->descriptor.idVendor) == USB_DELPHI_VENDOR_ID) &&
			((le16_to_cpu(compdev->descriptor.idProduct) & 0x0120) == 0x0120)) {
			break;
		}
	}
	if (compdev) {
		INFO_USB(dev,
			"Hub %d-%d P(%04x) V(%02x.%02x)\n",
			le16_to_cpu(dev->usbdev->parent->bus->busnum),
			le16_to_cpu(dev->usbdev->parent->devnum),
			le16_to_cpu(dev->usbdev->parent->descriptor.idProduct),
			le16_to_cpu(compdev->descriptor.bcdDevice) >> 8,
			le16_to_cpu(compdev->descriptor.bcdDevice) & 0xff
			);
	} else {
		INFO_USB(dev,
			"Hub %d-%d P(%04x) V(00.00)\n",
			le16_to_cpu(dev->usbdev->parent->bus->busnum),
			le16_to_cpu(dev->usbdev->parent->devnum),
			le16_to_cpu(dev->usbdev->parent->descriptor.idProduct)
			);
	}
}

static int dabridge_print_version(struct dabridge_usb *dev)
{
	int rv;
	u8 *buf = kmalloc(8, GFP_KERNEL);
	struct usb_ctrlrequest request;

	request.bRequestType = VEND_RD_BMREQTYPE;
	request.bRequest = VEND_RD_BREQ;
	request.wValue = 0;

	request.wIndex = cpu_to_le16(WINDEX_I_HW_IMAGE_VERSION);
	request.wLength = cpu_to_le16(2);
	if ((rv = dabridge_blocking_ctrl_rw(dev, CTRL_READ, &request, &buf[0])) < 0) {
		ERR_USB(dev, "Unable to read hardware revision\n");
		kfree(buf);
		return rv;
	}
	request.wIndex = cpu_to_le16(WINDEX_I_FIRMWARE_VERSION);
	request.wLength = cpu_to_le16(3);
	if ((rv = dabridge_blocking_ctrl_rw(dev, CTRL_READ, &request, &buf[2])) < 0) {
		ERR_USB(dev, "Unable to read firmware revision\n");
		kfree(buf);
		return rv;
	}
	INFO_USB(dev,
		"P(%04x) D(%s) F(%hhu.%hhu.%hhu) H(%hhu.%hhu) %s\n",
		dev->usbdev->descriptor.idProduct,
		H2H_DRIVER_VERSION,
		buf[4],
		buf[3],
		buf[2],
		buf[1],
		buf[0],
		usb_speed_string(dev->usbdev->speed));
	dabridge_print_hub_info(dev);
	kfree(buf);
	return 0;
}

static void dabridge_usb_reset_eps(struct dabridge_usb *dev)
{
	int i;
	struct usb_host_interface *iface_desc;
	struct usb_hcd *hcd = bus_to_hcd(dev->usbdev->bus);
	iface_desc = dev->interface->cur_altsetting;

	if (strstr(hcd->driver->description, "xhci") != NULL) {
		INFO_USB(dev, "Using xhci driver to reset endpoints\n");
		usb_set_interface(dev->usbdev, iface_desc->desc.bInterfaceNumber,
				iface_desc->desc.bAlternateSetting);
	} else {
		for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
			usb_reset_endpoint(dev->usbdev,
					iface_desc->endpoint[i].desc.bEndpointAddress);
		}
	}
}

static int dabridge_epflush_fifo(struct dabridge_usb *dev, u16 ep_bits)
{
	char buf[1];
	int rv;
	struct usb_ctrlrequest request;
	request.bRequestType = VEND_WR_BMREQTYPE;
	request.bRequest = VEND_WR_BREQ;
	request.wIndex = cpu_to_le16(WINDEX_O_FLUSH_EP_FIFO);
	request.wLength = 0;
	request.wValue = cpu_to_le16(ep_bits);
	rv = dabridge_blocking_ctrl_rw(dev, CTRL_WRITE, &request, buf);
	if (rv < 0) {
		ERR_USB(dev,
			"Unable to flush ep's 0x%02x fifo %d\n",
			ep_bits,
			rv);
	} else {
		dabridge_usb_reset_eps(dev);
	}
	return rv;
}

static ssize_t bridgeport_legacy_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	int busnum, devnum, portnum = 0;

	if (!strlen(active_bridgeport))
		goto end;

	if (sscanf(active_bridgeport, "%d-%d.%d",
		   &busnum, &devnum, &portnum) != 3) {
		pr_err("Failed to read active bridgeport\n");
		return -EINVAL;
	}
end:
	return sprintf(buf, "%d\n", portnum);
}

static ssize_t bridgeport_legacy_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	char sbuf[20];
	int busnum, devnum, portnum, ret;
	struct dabridge_usb *bridgedev = dev_get_drvdata(dev);

	if (!bridgedev)
		return -EINVAL;

	ret = kstrtoint(buf, 0, &portnum);
	if (ret < 0)
		return ret;

	/* Check if port is valid */
	if (portnum > MAX_BRIDGE_PORT || portnum < 0)
		return -EINVAL;

	busnum = bridgedev->usbdev->parent->bus->busnum;
	devnum = bridgedev->usbdev->parent->devnum;
	scnprintf(sbuf, sizeof(sbuf), "%d-%d.%d", busnum, devnum, portnum);

	/* Check to see if a port from a different H2H Hub is in bridge mode */
	if (strlen(active_bridgeport) &&
	    !sysfs_streq(sbuf, active_bridgeport)) {
		if (active_bridgedev && active_bridgedev != bridgedev) {
			ret = dabridge_port_role_reverse(active_bridgedev,
							 ALL_PORTS_AS_HOST);
			/* Clear active port */
			active_bridgeport[0] = '\0';
			active_bridgedev = NULL;
			if (ret < 0)
				return ret;
		}
	}

	/* Setup the new bridgeport */
	ret = dabridge_port_role_reverse(bridgedev, portnum);
	if (ret < 0)
		return ret;

	/* Track active port */
	strlcpy(active_bridgeport, sbuf, sizeof(active_bridgeport));
	active_bridgedev = bridgedev;

	return count;
}
static DEVICE_ATTR(bridgeport, 0644, bridgeport_legacy_show,
		   bridgeport_legacy_store);

/**
 * Set Downstream Port Power.
 * Ensure there are no control messages in queue prior to calling this function
 */
static int dabridge_port_power(struct dabridge_usb *dev, u8 port, u8 power)
{
	char buf[1];
	struct usb_ctrlrequest request;
	int rv;

	request.bRequestType = VEND_WR_BMREQTYPE;
	request.bRequest = VEND_WR_BREQ;
	request.wLength = 0;

	request.wIndex = cpu_to_le16(WINDEX_O_PORT_POWER);
	request.wValue = cpu_to_le16((power << 8) | port);
	if ((rv = dabridge_blocking_ctrl_rw(dev, CTRL_WRITE, &request, buf)) < 0) {
		ERR_USB(dev,
			"Failed setting port %hhu power to %s\n",
			port,
			power ? "On" : "Off");
	}

	return rv;
}

/**
 * Set a downstream port in Bridge mode.
 * Ensure there are no control messages in queue prior to calling this function.
 *
 * If successful returns the port Id, -1 on failure.
 */
static int dabridge_port_select(struct dabridge_usb *dev, int portId)
{
	char buf[1];
	struct usb_ctrlrequest request;
	unsigned w_value_dn1;
	unsigned w_value_dn2;
	int rv;

	request.bRequestType = VEND_WR_BMREQTYPE;
	request.bRequest = VEND_WR_BREQ;
	request.wIndex = 0;
	request.wLength = 0;

	/* Flush all endpoints fifo when H2H is enabled */
	if(portId && (rv = dabridge_epflush_fifo(dev, 0xff)) < 0) {
		goto w_error;
	}

	if(dev->info->new_apis) {
		/* Using the new vendor request */
		request.wIndex = cpu_to_le16(WINDEX_O_SELECT_BRIDGE_PORT);
		request.wValue = cpu_to_le16(portId);
		if((rv = dabridge_blocking_ctrl_rw(dev, CTRL_WRITE,
				&request, buf)) < 0) {
			ERR_USB(dev,
				"Setting port %d into bridge mode failed\n",
				(portId - dev->info->port_num_offset));
			goto w_error;
		}
		goto w_done;
	}

	/* Using the legacy vendor request */
	switch (portId) {
	case 0: /* Bridge mode disabled */
		w_value_dn1 = WVALUE_DN1_HUB;
		w_value_dn2 = WVALUE_DN2_HUB;
		break;
	case 1:
		w_value_dn1 = WVALUE_DN1_BRIDGE;
		w_value_dn2 = WVALUE_DN2_HUB;
		break;
	case 2:
		w_value_dn1 = WVALUE_DN1_HUB;
		w_value_dn2 = WVALUE_DN2_BRIDGE;
		break;
	default:
		return -EINVAL;
		break;
	}

	if(portId) {
		request.wIndex = cpu_to_le16(WINDEX_O_MUX_BRIDGE_DN_SEL);
		request.wValue = cpu_to_le16(portId - 1);
		if((rv = dabridge_blocking_ctrl_rw(dev, CTRL_WRITE,
				&request, buf)) < 0) {
			ERR_USB(dev,
				"Selecting DN%d into bridge mode failed\n",
				portId);
			goto w_error;
		}
	} else {
		/* If the bridge was previously connected to a port,
		 * switch to another port to simulate a disconnect.
		 */
		if(dev->connectedport > 0) {
			request.wIndex = cpu_to_le16(WINDEX_O_MUX_BRIDGE_DN_SEL);
			request.wValue = cpu_to_le16((dev->connectedport == 2)?0:1);
			if((rv = dabridge_blocking_ctrl_rw(dev, CTRL_WRITE,
					&request, buf)) < 0) {
				ERR_USB(dev, "Selecting bridge mux failed\n");
				goto w_error;
			}
		}
	}

	msleep(10);

	/* Setup downstream port mux's*/
	request.wIndex = cpu_to_le16(WINDEX_O_MUX_SELECT_DN1);
	request.wValue = cpu_to_le16(w_value_dn1);
	if((rv = dabridge_blocking_ctrl_rw(dev,
			CTRL_WRITE, &request, buf)) < 0) {
		ERR_USB(dev, "DN1 mux select failed\n");
		goto w_error;
	}
	request.wIndex = cpu_to_le16(WINDEX_O_MUX_SELECT_DN2);
	request.wValue = cpu_to_le16(w_value_dn2);
	if((rv = dabridge_blocking_ctrl_rw(dev,
			CTRL_WRITE, &request, buf)) < 0) {
		ERR_USB(dev, "DN2 mux select failed\n");
		goto w_error;
	}

w_done:
	if(portId) {
		INFO_USB(dev, "Downstream port %d in bridge mode\n",
			(portId - dev->info->port_num_offset) );
	} else {
		INFO_USB(dev, "All downstream ports in host mode\n");
	}

	rv = portId;

w_error:
	dev->connectedport = rv;
	return rv;
}

static int dabridge_port_reset(struct dabridge_usb *brdev)
{
	int retval = 0;
	int busnum, devnum, portnum;

	/* Get the active bridge port */
	if (strlen(active_bridgeport)
		&& sscanf(active_bridgeport, "%d-%d.%d",
				&busnum,
				&devnum,
				&portnum) == 3) {

		/* Check if any port was in bridge mode prior to reset */
		if (dabridge_is_h2h_hub(brdev->usbdev->parent, busnum, devnum) &&
				portnum) {

			INFO_USB(brdev, "Toggle bridge port '%d-%d.%d' power\n",
					busnum,
					devnum,
					portnum);

			active_bridgeport[0] = '\0';
			portnum += brdev->info->port_num_offset;
			/* Port VBUS Off */
			if ((retval = dabridge_port_power(brdev, portnum, 0)) < 0) {
				goto reset_exit;
			}
			msleep(brdev->info->port_switch_wait);
			/* Port VBUS On */
			if ((retval = dabridge_port_power(brdev, portnum, 1)) < 0) {
				goto reset_exit;
			}
		}
	}

	retval = dabridge_port_select(brdev, 0);

reset_exit:
	return retval;
}

static DEFINE_IDA(da_ida);

static int dabridge_probe(struct usb_interface *interface,
		const struct usb_device_id *usbid)
{
	struct usb_host_interface *iface_desc;
	struct dabridge_usb *the_bridge;
	struct platform_device *dabr_udc_pdev;
	int i, id;
	int retval = -ENOMEM;

	if (!usbid->driver_info)
		return retval;

	/* allocate memory for our device state and initialize it */
	the_bridge = kzalloc(sizeof(*the_bridge), GFP_KERNEL);
	if (!the_bridge) {
		dev_err(&interface->dev, "Out of memory\n");
		goto error;
	}
	kref_init(&the_bridge->kref);
	mutex_init(&the_bridge->io_mutex);

	/*increments the reference count of the usb device*/
	the_bridge->usbdev = usb_get_dev(interface_to_usbdev(interface));
	the_bridge->interface = interface;
	the_bridge->info = (void *)usbid->driver_info;

	/* set up the endpoint information */
	iface_desc = interface->cur_altsetting;
	for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {

		DBG_USB(the_bridge, "eps[%d]= ep%d%s-%s maxpacket %d\n",
			i,
			iface_desc->endpoint[i].desc.bEndpointAddress & 0x0f,
			(iface_desc->endpoint[i].desc.bEndpointAddress & USB_DIR_IN) ? "in" : "out",
			({ char *val;
			 switch (iface_desc->endpoint[i].desc.bmAttributes & 0x03) {
			 case USB_ENDPOINT_XFER_BULK: val = "bulk"; break;
			 case USB_ENDPOINT_XFER_ISOC: val = "iso"; break;
			 case USB_ENDPOINT_XFER_INT: val = "int"; break;
			 default: val = "ctrl"; break;
			 }; val; }),
			 usb_endpoint_maxp(&iface_desc->endpoint[i].desc));

	}

	/* save our data pointer in this interface device */
	usb_set_intfdata(interface, the_bridge);

	snprintf(the_bridge->name, sizeof(the_bridge->name),
			"%s %d-%d", dabridge_driver_name,
			the_bridge->usbdev->bus->busnum,
			the_bridge->usbdev->devnum);

	/* let the user know about this device */
	INFO_USB(the_bridge,
		"%s total endpoints=%d, %p\n",
		the_bridge->name,
		iface_desc->desc.bNumEndpoints,
		the_bridge);

	/* Print Hardware Info*/
	if ((retval = dabridge_print_version(the_bridge)) < 0)
		goto error;

	/* Configure all downstream port to Hub mode */
	if ((retval = dabridge_port_reset(the_bridge)) < 0)
		goto error;

	id = ida_simple_get(&da_ida, 0, 0, GFP_KERNEL);
	if (id < 0) {
		dev_err(&interface->dev, "Could not get device id\n");
		retval = id;
		goto error;
	}

	dabr_udc_pdev = platform_device_alloc(dabridge_gadget_name, id);
	if (!dabr_udc_pdev) {
		retval = -ENOMEM;
		goto err_plat_alloc;
	}
	dabr_udc_pdev->dev.parent = &interface->dev;

	retval = platform_device_add(dabr_udc_pdev);
	if (retval < 0)
		goto err_add_udc;

	retval = device_create_file(&the_bridge->interface->dev,
				    &dev_attr_bridgeport);
	if (retval)
		goto err_dev_attr_bport;

	/* Add this device to our list of devices */
	mutex_lock(&device_list_lock);
	list_add(&the_bridge->device_list, &dabridge_device_list);
	dabridge_device_count++;
	mutex_unlock(&device_list_lock);

	return 0;

err_dev_attr_bport:
	platform_device_del(dabr_udc_pdev);
err_add_udc:
	platform_device_put(dabr_udc_pdev);
err_plat_alloc:
	ida_simple_remove(&da_ida, id);
error:
	if (the_bridge) {
		/* this frees allocated memory */
		kref_put(&the_bridge->kref, dabridge_device_delete);
	}
	return retval;
}

static void dabridge_disconnect(struct usb_interface *interface)
{
	struct dabridge_usb *brdev = usb_get_intfdata(interface);
	int id;

	dabridge_udc_endpoint_transfers(brdev, STOP_UDC_XFER);

	device_remove_file(&brdev->interface->dev,
			   &dev_attr_bridgeport);

	if (brdev->udc && brdev->udc->pdev) {
		id = brdev->udc->pdev->id;
		platform_device_unregister(brdev->udc->pdev);
		ida_simple_remove(&da_ida, id);
	}

	usb_set_intfdata(interface, NULL);

	/* prevent more I/O from starting */
	mutex_lock(&brdev->io_mutex);
	brdev->interface = NULL;
	mutex_unlock(&brdev->io_mutex);

	/* Delete from list of devices */
	mutex_lock(&device_list_lock);
	list_del(&brdev->device_list);
	dabridge_device_count--;
	mutex_unlock(&device_list_lock);

	/* decrement our usage count */
	kref_put(&brdev->kref, dabridge_device_delete);
}

static int dabridge_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct dabridge_usb *dev = usb_get_intfdata(intf);

	if (dev) {
		INFO_USB(dev, "Suspend %s\n", dev->name);
	}

	return 0;
}

static int dabridge_resume(struct usb_interface *intf)
{
	struct dabridge_usb *dev = usb_get_intfdata(intf);

	if (dev) {
		INFO_USB(dev, "Resume %s\n", dev->name);
	}

	return 0;
}

static int dabridge_pre_reset(struct usb_interface *intf)
{
	struct dabridge_usb *dev = usb_get_intfdata(intf);

	if (dev) {
		INFO_USB(dev, "Pre-Reset %s\n", dev->name);
	}

	return 0;
}

static int dabridge_post_reset(struct usb_interface *intf)
{
	struct dabridge_usb *dev = usb_get_intfdata(intf);

	if (dev) {
		INFO_USB(dev, "Post-Reset %s\n", dev->name);
		/* Uncomment the following if the post-reset is called
		 * instead of USB disconnect for device/hub port reset */
		/*dabridge_port_reset(dev);*/
	}

	return 0;
}

static int dabridge_port_role_reverse(struct dabridge_usb *brdev, int portnum)
{
	int ret = 0;
	u8 vbusport = 0;

	dabridge_udc_endpoint_transfers(brdev, STOP_UDC_XFER);

	if (portnum) {
		portnum += brdev->info->port_num_offset;
	}

	if (brdev->info->new_apis && (brdev->connectedport > 0)
			&& (brdev->connectedport != portnum)) {
		/* Switch VBUS OFF for the port that
		 * was previously in bridge mode */
		vbusport = (u8)brdev->connectedport;

		DBG_USB(brdev, "Port %d VBUS OFF\n",
				(vbusport - brdev->info->port_num_offset));
		if ((ret = dabridge_port_power(brdev, vbusport, 0)) < 0) {
			goto ret_error;
		}
	}

	if ((ret = dabridge_port_select(brdev, portnum)) < 0) {
		goto ret_error;
	}

	if (portnum || vbusport) {
		msleep(brdev->info->port_switch_wait);
		if (vbusport) {
			/* Restore VBUS for the port that
			 * was previously in bridge mode */
			if ((ret = dabridge_port_power(brdev, vbusport, 1))
					< 0) {
				goto ret_error;
			}
			DBG_USB(brdev, "Port %d VBUS ON\n",
					(vbusport - brdev->info->port_num_offset));
		}
	}

	/* Start UDC if H2H bridge is enabled */
	if (portnum)
		dabridge_udc_endpoint_transfers(brdev, START_UDC_XFER);

	smp_mb();
	return 0;

ret_error:
	return ret;
}

void dabridge_reset_role_reversal(struct dabridge_usb *brdev) {
	int busnum, devnum, portnum;

        /* Get the active bridge port */
        if (strlen(active_bridgeport)
                && sscanf(active_bridgeport, "%d-%d.%d",
                                &busnum,
                                &devnum,
                                &portnum) == 3) {
		if (portnum == 0)
			return;

		dabridge_port_role_reverse(brdev,ALL_PORTS_AS_HOST);
		dabridge_port_role_reverse(brdev,portnum);
	}
}


static inline bool dabridge_is_h2h_hub(struct usb_device *hdev, int busnum,
		int devnum)
{
	if ((hdev->devnum == devnum)
		&& (hdev->bus->busnum == busnum)
		&& (hdev->descriptor.bDeviceClass == USB_CLASS_HUB)
		&& (hdev->descriptor.idVendor == USB_UNWIRED_VENDOR_ID
		|| hdev->descriptor.idVendor == USB_DELPHI_VENDOR_ID
		|| hdev->descriptor.idVendor == USB_UIPHUB_VENDOR_ID)) {
		return true;
	}
	return false;
}

/*
 * Recognized Format
 * BUSNUM-HUBDEVNUM.PORT
 * TODO: BUSNUM-BRIDGEDEVNUM=PORT
 * TODO: PORT (legacy)
 *
 * returns the pointer to the device on success or NULL on error
 * populates the decoded port number and/or port power state
 */
static struct dabridge_usb *dabridge_parse_portstring(const char *buf,
		int *portn, u8 *ppower)
{
	int busnum, devnum, portnum;
	struct dabridge_usb *tmpdev;
	bool devfound = false;

	if (list_empty(&dabridge_device_list))
		goto err_no_device;

	if (ppower) {
		if (sscanf(buf, "%d-%d.%d=%hhu",
				&busnum, &devnum, &portnum, ppower) != 4)
			goto err_invalid;
	} else if (sscanf(buf, "%d-%d.%d", &busnum, &devnum, &portnum) != 3) {
		goto err_invalid;
	}

	if (portnum > MAX_BRIDGE_PORT || portnum < 0) {
		pr_err("%s: Out of range Port %i, must be between 0-%d\n",
				dabridge_driver_name,
				portnum,
				MAX_BRIDGE_PORT);
		*portn = -ERANGE;
		return NULL;
	}

	mutex_lock(&device_list_lock);
	list_for_each_entry(tmpdev, &dabridge_device_list, device_list)
	{
		if (dabridge_is_h2h_hub(tmpdev->usbdev->parent,
				busnum,
				devnum)) {
			devfound = true;
			break;
		}
	}
	mutex_unlock(&device_list_lock);

err_no_device:
	if (!devfound) {
		pr_err("%s: No H2H Bridge device for '%s'\n",
				dabridge_driver_name,
				buf);
		*portn = -ENODEV;
		return NULL;
	}
	*portn = portnum;
	return tmpdev;

err_invalid:
	pr_err("%s: Invalid bridgeport format '%s'\n",
			dabridge_driver_name,
			buf);
	*portn = -EINVAL;
	return NULL;
}

static ssize_t bridgeport_show(struct device_driver *driver, char *buf)
{
	//struct usb_driver *usb_drv = to_usb_driver(driver);
	struct dabridge_usb *tmpdev;

	buf[0] = 0;
	mutex_lock(&device_list_lock);
	list_for_each_entry(tmpdev, &dabridge_device_list, device_list)
	{
		scnprintf(buf, PAGE_SIZE,"%sAvailable[Bus#-HubDev#.Port]: %d-%d.x\n",
				buf, tmpdev->usbdev->parent->bus->busnum,
				tmpdev->usbdev->parent->devnum);
	}
	mutex_unlock(&device_list_lock);

	return scnprintf(buf, PAGE_SIZE, "%sActive: %s\n", buf,
			strlen(active_bridgeport) ?
			active_bridgeport : "No ports in Bridge mode");
}

static ssize_t bridgeport_store(struct device_driver *driver,
			    const char *buf, size_t count)
{
	//struct usb_driver *usb_drv = to_usb_driver(driver);
	int ret, portnum;
	char sbuf[20], *end;
	struct dabridge_usb *bridgedev = NULL;

	/* Strip newline */
	strlcpy(sbuf, buf, sizeof(sbuf));
	if((end = strchr(sbuf, '\n')) != NULL)
		*end = '\0';

	bridgedev = dabridge_parse_portstring(sbuf, &portnum, NULL);
	if (bridgedev == NULL) {
		return portnum;
	}

	/* Check to see if a port from a different H2H Hub is in bridge mode */
	if (strlen(active_bridgeport) && !sysfs_streq(sbuf, active_bridgeport)) {
		pr_info("%s: prev bridgeport '%s'\n",
				dabridge_driver_name,
				active_bridgeport);
		if (active_bridgedev && active_bridgedev != bridgedev) {
			ret = dabridge_port_role_reverse(active_bridgedev,
					ALL_PORTS_AS_HOST);
			/* Clear active port */
			active_bridgeport[0] = '\0';
			active_bridgedev = NULL;
			if (ret < 0)
				return ret;
		}
	}

	pr_info("%s: new  bridgeport '%s'\n", dabridge_driver_name, sbuf);

	/* Setup the new bridgeport */
	ret = dabridge_port_role_reverse(bridgedev, portnum);
	if(ret < 0)
		return ret;

	if (!portnum && strlen(active_bridgeport))
		dabridge_epflush_fifo(bridgedev, 0xff);

	/* Track active port */
	strlcpy(active_bridgeport, sbuf, sizeof(active_bridgeport));
	active_bridgedev = bridgedev;

	return count;
}
/* path to this attribute "/sys/bus/usb/drivers/dabridge/bridgeport" */
static DRIVER_ATTR_RW(bridgeport);

static ssize_t portpower_show(struct device_driver *driver, char *buf)
{
	return scnprintf(buf,
			PAGE_SIZE,
			"To control port power\n BUSNUM-HUBDEVNUM.PORT=<1|0>\n");
}

static ssize_t portpower_store(struct device_driver *driver,
			    const char *buf, size_t count)
{
	int ret, portnum;
	u8 power;
	char sbuf[20], *end;
	struct dabridge_usb *bridgedev = NULL;

	/* Strip newline */
	strlcpy(sbuf, buf, sizeof(sbuf));
	if((end = strchr(sbuf, '\n')) != NULL)
		*end = '\0';

	bridgedev = dabridge_parse_portstring(sbuf, &portnum, &power);
	if (bridgedev == NULL) {
		return portnum;
	}

	dabridge_udc_endpoint_transfers(bridgedev, STOP_UDC_XFER);

	if(portnum) {
		portnum += bridgedev->info->port_num_offset;
	}

	ret = dabridge_port_power(bridgedev, portnum, power);

	if(bridgedev->connectedport > 0) {
		/* Start UDC if H2H bridge is enabled */
		dabridge_udc_endpoint_transfers(bridgedev, START_UDC_XFER);
	}

	if(ret < 0) {
		return ret;
	} else {
		INFO_USB(bridgedev, "Port-%d power set to %s\n",
				(portnum - bridgedev->info->port_num_offset),
				power ? "On" : "Off");
		return count;
	}
	return count;
}
/* path to this attribute "/sys/bus/usb/drivers/dabridge/portpower" */
static DRIVER_ATTR_RW(portpower);

static struct attribute *dabridge_drv_attrs[] = {
	&driver_attr_bridgeport.attr,
	&driver_attr_portpower.attr,
	NULL
};

static struct attribute_group dabridge_drv_attr_grp = {
	.attrs = dabridge_drv_attrs,
};

static const struct attribute_group *dabridge_drv_attr_grps[] = {
	&dabridge_drv_attr_grp,
	NULL
};

static struct usb_driver dabridge_driver = {
	.name       = dabridge_driver_name,
	.probe      = dabridge_probe,
	.disconnect = dabridge_disconnect,
	.suspend    = dabridge_suspend,
	.resume     = dabridge_resume,
	.pre_reset  = dabridge_pre_reset,
	.post_reset = dabridge_post_reset,
	.id_table   = dabridge_usb_table,
	.no_dynamic_id = 1,
	.supports_autosuspend = 1,
	.drvwrap = {
		.driver = {
			.groups = dabridge_drv_attr_grps,
		},
	},
};

static int __init init(void)
{
	int retval = -ENOMEM;

	if (usb_disabled())
		return -ENODEV;

	/* register this driver with the USB subsystem */
	retval = usb_register(&dabridge_driver);
	if (retval) {
		pr_err("usb_register failed. Error number %d", retval);
		return retval;
	}

	retval = platform_driver_register(&dabridge_udc_driver);
	if (retval < 0) {
		pr_err("cannot register platform driver.\n");
		goto err_reg_platform_driver;
	}

	return 0;

err_reg_platform_driver:
	usb_deregister(&dabridge_driver);
	return retval;
}
module_init (init);

static void __exit cleanup(void)
{
	/* Deregister the driver
	 * This will cause disconnect() to be called for each
	 * attached unit
	 */
	platform_driver_unregister(&dabridge_udc_driver);

	/* deregister this driver with the USB subsystem */
	usb_deregister(&dabridge_driver);
}
module_exit (cleanup);
