/*
 * dabridge.h
 *
 *  Copyright (c) 2015, Delphi Automotive PLC
 *  Created on: Jan 16, 2015
 *      Author: Sam Yeda <sam.yeda@delphi.com>
 *
 *  Revision History
 *  Sam Yeda        26OCT2015,  Beta release.
 *  Sam Yeda        13JUN2016,  Add Delphi Vendor ID.
 *  Sam Yeda        28FEB2017,  Change struct dabridge_udc variable types for alignment.
 *  Sam Yeda        20MAY2017,  Re-locate urb in struct dabridge_request to support some SOC's.
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

#ifndef DRIVER_DABRIDGE_H_
#define DRIVER_DABRIDGE_H_

#define H2H_DRIVER_DESC    "Delphi H2H Bridge driver with Gadget/UDC Interface"
#define H2H_DRIVER_VERSION "20.08.10"

#define USB_DELPHI_VENDOR_ID     0x2C48
#define USB_UNWIRED_VENDOR_ID    0x2996
#define USB_UIPHUB_VENDOR_ID     0x0451 /* Bridge is connected to this UIP Hub */
#define USB_HILN_100_PRODUCT_ID  0x0100 /* production */
#define USB_ASIC_101_PRODUCT_ID  0x0101 /* production */
#define USB_ASIC_102_PRODUCT_ID  0x0102 /* production */

#define USB_HILN_104_PRODUCT_ID  0x0104 /* production with in/out isoc endpoint*/
#define USB_ASIC_105_PRODUCT_ID  0x0105 /* production without isoc endpoint */

#define ERR_USB(tdev, fmt, args...) \
        dev_err(&tdev->interface->dev, fmt, ## args)
#define DBG_USB(tdev, fmt, args...) \
        dev_dbg(&tdev->interface->dev, fmt, ## args)
#define INFO_USB(tdev, fmt, args...) \
        dev_info(&tdev->interface->dev, fmt, ## args)

#define MAX_BRIDGE_ENDPOINTS  8
#define MAX_BRIDGE_PORT       4
#define MAX_USB_EP0_PACKET    64

#define CTRL_READ             1
#define CTRL_WRITE            0
#define CTRL_MSG_TIMEOUT      500
#define ALL_PORTS_AS_HOST     0

#define START_UDC_XFER        1
#define STOP_UDC_XFER         0

#define USB_REQ_BHOST_DISCONNECTED 0xFF

#define VEND_WR_BMREQTYPE          (0x40)
#define VEND_RD_BMREQTYPE          (0xC0)
#define VEND_WR_BREQ               (0x02)
#define VEND_RD_BREQ               (0x01)

#define PROCESS_WVALUE_DATA         0x0001
#define STORE_WVALUE_IN_FPGA        0x0002
#define STORE_DATA_IN_FPGA          0x0004
#define SEND_DATA_TO_PHY_HOST       0x0008
#define CLASS_SPECIFIC_REQ          0x1000
#define VENDOR_SPECIFIC_REQ         0x2000

#define WINDEX_WRITE_REQUEST        (VENDOR_SPECIFIC_REQ | PROCESS_WVALUE_DATA | STORE_WVALUE_IN_FPGA)
#define WINDEX_IBREQUEST_SHIFT      4
#define WINDEX_I_FIRMWARE_VERSION   (VENDOR_SPECIFIC_REQ  | (0 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_I_THERMAL_GOOD       (VENDOR_SPECIFIC_REQ  | (1 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_O_MUX_SELECT_DN1     (WINDEX_WRITE_REQUEST | (2 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_O_MUX_SELECT_DN2     (WINDEX_WRITE_REQUEST | (3 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_O_MUX_BRIDGE_DN_SEL  (WINDEX_WRITE_REQUEST | (4 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_I_DN1_POWER_STATUS   (VENDOR_SPECIFIC_REQ  | (5 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_O_DN1_POWER_ENABLE   (WINDEX_WRITE_REQUEST | (6 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_I_DN2_POWER_STATUS   (VENDOR_SPECIFIC_REQ  | (7 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_O_DN2_POWER_ENABLE   (WINDEX_WRITE_REQUEST | (8 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_I_DN1_OVER_CURRENT   (VENDOR_SPECIFIC_REQ  | (9 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_I_DN2_OVER_CURRENT   (VENDOR_SPECIFIC_REQ  | (10 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_O_DIMMING_BRIDGE     (WINDEX_WRITE_REQUEST | (11 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_O_BRIDGE_OVERCURRENT (WINDEX_WRITE_REQUEST | (12 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_I_POWER_GOOD         (VENDOR_SPECIFIC_REQ  | (13 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_I_HW_IMAGE_VERSION   (VENDOR_SPECIFIC_REQ  | (14 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_O_FLUSH_EP_FIFO      (WINDEX_WRITE_REQUEST | (15 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_I_BHOST_STATUS       (VENDOR_SPECIFIC_REQ  | (16 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_O_SELECT_BRIDGE_PORT (WINDEX_WRITE_REQUEST | (17 << WINDEX_IBREQUEST_SHIFT))
#define WINDEX_O_PORT_POWER         (WINDEX_WRITE_REQUEST | (18 << WINDEX_IBREQUEST_SHIFT))

#define WVALUE_DN1_HUB    0
#define WVALUE_DN1_BRIDGE 1
#define WVALUE_DN2_HUB    1
#define WVALUE_DN2_BRIDGE 0

enum dabridge_ctrl_state {
	DABR_CTRL_SETUP,
	DABR_CTRL_DATA_IN,
	DABR_CTRL_DATA_OUT,
	DABR_CTRL_STATUS_IN,
	DABR_CTRL_STATUS_OUT,
};
enum dabridge_udc_state {
	DABRIDGE_UDC_STOPPED,
	DABRIDGE_UDC_SUSPENDED,
	DABRIDGE_UDC_RUNNING
};

struct dabridge_info {
	const char **ep_names; /* endpoint names array*/
	int  num_of_ep_names;  /* number of names */
	u8   isoc_in_ep;       /* isoc in endpoint override */
	u8   isoc_out_ep;      /* isoc out endpoint override */
	int  port_num_offset;  /* port number offset */
	uint port_switch_wait; /* milliseconds to wait after port switch */
	u8   new_apis;         /* whether to use new vendor requests */
};

/* Structure to hold all of our USB device specific stuff */
struct dabridge_usb {
	struct list_head     device_list;
	struct usb_device    *usbdev;    /* the usb device for this device */
	struct usb_interface *interface; /* the interface for this device */
	struct dabridge_info *info; /* usb device specific info */
	struct dabridge_udc  *udc; /* UDC */
	struct kref  kref;         /* reference counter */
	struct mutex io_mutex;     /* synchronize I/O with disconnect */
	int connectedport;         /* hub port connected to bridge*/
	char name[20];             /* Some Unique Name */
};
#define kref_to_dabridge_usb(d) container_of(d, struct dabridge_usb, kref)
#define usbdev_to_dabridge_usb(d) container_of(d, struct dabridge_usb, usbdev)

/* gadget side driver data structures */
struct dabr_g_ep {
	struct list_head  queue;
	unsigned long     last_io;	/* jiffies timestamp */
	struct usb_gadget *gadget;
	const struct usb_endpoint_descriptor *desc;    /* Gadget */
	const struct usb_endpoint_descriptor *br_desc; /* Gadget <=> Bridge */
	struct usb_anchor submitted; /* track urb submissions */
	struct usb_ep ep;
	spinlock_t   lock;
	int          qlen;
	unsigned     halted : 1;
	unsigned     wedged : 1;
};
static inline struct dabr_g_ep *usb_ep_to_dabr_g_ep(struct usb_ep *_ep) {
	return container_of (_ep, struct dabr_g_ep, ep);
}

struct dabridge_request {
	struct list_head   queue; /* ep's requests */
	gfp_t              mem_flags;
	struct usb_request req;
	int                count;
	struct urb         *urb;   /* the urb to read/write data with */
	unsigned	   unlinked:1;
};
static inline struct dabridge_request *usb_request_to_dabridge_request(
		struct usb_request *_req) {
	return container_of (_req, struct dabridge_request, req);
}

struct dabridge_udc {
	struct kref kref;         /* reference counter */

	/* GADGET side support */
	struct usb_gadget_driver *driver;
	struct dabr_g_ep  eps[MAX_BRIDGE_ENDPOINTS];
	struct usb_gadget gadget;
	unsigned  address;
	unsigned  devstatus;
	unsigned  pullup;

	/* BRIDGE side support */
	struct dabridge_usb *bridgedev;

	/* UDC */
	struct platform_device *pdev;
	struct work_struct     state_work;
	enum dabridge_udc_state state;
	spinlock_t lock;
	unsigned   resuming;

	struct usb_ctrlrequest   ahost_ctrl_req; /* Vendor setup request to Bridge  */
	struct usb_ctrlrequest   ahost_ctrl_rsp; /* Vendor setup response to Bridge */
	struct usb_request      *bhost_usb_req;  /* Request for B-Host setup packet */
	enum dabridge_ctrl_state ctrl_state;
	enum usb_device_state    bhoststate;
};
#define kref_to_dabridge_udc(d) container_of(d, struct dabridge_udc, kref)

static inline struct device *udc_dev(struct dabridge_udc *cntroller) {
	return cntroller->gadget.dev.parent;
}

static inline struct dabridge_udc *ep_to_cntroller(struct dabr_g_ep *ep) {
	return container_of (ep->gadget, struct dabridge_udc, gadget);
}

static inline struct dabridge_udc *gadget_to_cntroller(
		struct usb_gadget *gadget) {
	return container_of(gadget, struct dabridge_udc, gadget);
}

static inline struct dabridge_udc *gadget_dev_to_cntroller(struct device *dev) {
	return container_of (dev, struct dabridge_udc, gadget.dev);
}

static inline struct dabridge_udc *state_work_to_cntroller(struct work_struct *w) {
	return container_of(w, struct dabridge_udc, state_work);
}

int dabridge_udc_endpoint_transfers(struct dabridge_usb *brdev, int is_start);
void dabridge_reset_role_reversal(struct dabridge_usb *brdev);
extern struct platform_driver dabridge_udc_driver;

#endif /* DRIVER_DABRIDGE_H_ */
