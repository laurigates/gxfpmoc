/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_GXFP_H
#define _UAPI_LINUX_GXFP_H

#include <linux/types.h>
#include <linux/ioctl.h>

/*
 * Goodix GXFP5130 EC mailbox transport.
 *
 * The kernel owns the ACPI-described mailbox window, the two GpioIo strobe
 * outputs and the GpioInt doorbell.
 *
 *   write(2)  submit one raw TX frame (maximum GXFP_TX_MAX bytes).
 *             The kernel copies the frame into the TX window and pulses
 *             write-done.
 *
 *   read(2)   return one raw RX chunk. The record length is
 *             currently fixed to GXFP_RX_MAX.
 *
 *   poll(2)   report POLLIN while a complete RX record is queued.
 */

#define GXFP_IOCTL_MAGIC	0x3F

#define GXFP_TX_MAX		0x200u
#define GXFP_RX_MAX		0xE00u

/**
 * struct gxfp_rx_record - one opaque RX chunk
 * @len: number of valid bytes in @data (currently GXFP_RX_MAX)
 * @reserved: must be zero
 * @timestamp_ns: CLOCK_MONOTONIC timestamp captured before the RX read
 * @data: raw RX window bytes
 */
struct gxfp_rx_record {
	__u32 len;
	__u32 reserved;
	__u64 timestamp_ns;
	__u8 data[];
};

#define GXFP_RX_RECORD_SIZE \
	(sizeof(struct gxfp_rx_record) + GXFP_RX_MAX)

/* Discard all queued RX records. */
#define GXFP_IOCTL_FLUSH_RX	_IO(GXFP_IOCTL_MAGIC, 0x00)

/*
 * Transport variants.
 *
 * GXFP_VARIANT_5130: the layout described above. TX frames carry the
 *   8-byte mailbox wrapper and RX records are fixed GXFP_RX_MAX chunks.
 *
 * GXFP_VARIANT_51B7: MateBook X Pro 2020 (ACPI GXFP51B7). TX frames are
 *   written unwrapped and the doorbell is ACPI _DSM function 2. Each RX
 *   record holds one complete frame: the 4-byte header followed by its
 *   payload, so @len is 4 + the header's length field. Records are
 *   sizeof(struct gxfp_rx_record) + gxfp_info.rx_max bytes long.
 */
#define GXFP_VARIANT_5130	0u
#define GXFP_VARIANT_51B7	1u

/**
 * struct gxfp_info - transport parameters of the bound device
 * @variant: GXFP_VARIANT_*
 * @tx_max: largest write(2) accepted, in bytes
 * @rx_max: largest record payload; read(2) needs a buffer of
 *          sizeof(struct gxfp_rx_record) + @rx_max bytes
 * @reserved: zero
 */
struct gxfp_info {
	__u32 variant;
	__u32 tx_max;
	__u32 rx_max;
	__u32 reserved;
};

/* Report the transport parameters. Absent (ENOTTY) on older kernels: assume 5130. */
#define GXFP_IOCTL_GET_INFO	_IOR(GXFP_IOCTL_MAGIC, 0x01, struct gxfp_info)

#endif /* _UAPI_LINUX_GXFP_H */
