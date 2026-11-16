// SPDX-License-Identifier: GPL-2.0-only
/*
 * Debug helper: evaluate _DSM function 1 (cc58b68a-..., rev 0) on the
 * GXFP51B7 ACPI device and expose the returned buffer as
 * /sys/kernel/debug/gxfp_dsm1. Read-only; for bring-up only.
 */
#include <linux/acpi.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/slab.h>

static const guid_t dsm_guid =
	GUID_INIT(0xcc58b68a, 0x4479, 0x4893,
		  0xa8, 0xbb, 0x96, 0x12, 0x09, 0xdb, 0x59, 0xe5);

static struct debugfs_blob_wrapper blob;
static struct dentry *file;

static int __init dsm_dump_init(void)
{
	struct acpi_device *adev;
	union acpi_object *obj;

	adev = acpi_dev_get_first_match_dev("GXFP51B7", NULL, -1);
	if (!adev)
		return -ENODEV;

	obj = acpi_evaluate_dsm_typed(adev->handle, &dsm_guid, 0, 1, NULL,
				      ACPI_TYPE_BUFFER);
	acpi_dev_put(adev);
	if (!obj)
		return -EIO;

	blob.data = kmemdup(obj->buffer.pointer, obj->buffer.length, GFP_KERNEL);
	blob.size = obj->buffer.length;
	ACPI_FREE(obj);
	if (!blob.data)
		return -ENOMEM;

	file = debugfs_create_blob("gxfp_dsm1", 0400, NULL, &blob);
	pr_info("gxfp_dsm_dump: %lu bytes\n", blob.size);
	return 0;
}

static void __exit dsm_dump_exit(void)
{
	debugfs_remove(file);
	kfree(blob.data);
}

module_init(dsm_dump_init);
module_exit(dsm_dump_exit);
MODULE_DESCRIPTION("Dump GXFP51B7 _DSM function 1 (bring-up debug)");
MODULE_LICENSE("GPL");
