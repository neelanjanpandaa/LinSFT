// SPDX-License-Identifier: GPL-2.0
/*
 * securemon - LinSFT system-monitor character device.
 *
 * Exposes live kernel-side statistics as key=value text on /dev/securemon (read-only).
 * Operations implemented: open, read, release. There is NO write, ioctl, proc or sysfs interface.
 * The LinSFT server (server/src/system_monitor.cpp) reads this device on every SYSINFO request.
 */
#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/version.h>

#define DEVICE_NAME "securemon"
#define SM_BUF_SIZE 512

static dev_t sm_devno;
static struct cdev sm_cdev;
static struct class *sm_class;
static atomic_t sm_open_count = ATOMIC_INIT(0);
static atomic_t sm_read_count = ATOMIC_INIT(0);

static int sm_open(struct inode *inode, struct file *filp)
{
	int n = atomic_inc_return(&sm_open_count);

	pr_info("securemon: device opened (total opens: %d)\n", n);
	return 0;
}

static int sm_release(struct inode *inode, struct file *filp)
{
	pr_info("securemon: device released\n");
	return 0;
}

static ssize_t sm_read(struct file *filp, char __user *ubuf, size_t count, loff_t *ppos)
{
	struct sysinfo si;
	char *kbuf;
	int len;
	ssize_t ret;

	kbuf = kmalloc(SM_BUF_SIZE, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	si_meminfo(&si);
	atomic_inc(&sm_read_count);

	len = scnprintf(kbuf, SM_BUF_SIZE,
			"securemon_version=1.0\n"
			"uptime_s=%llu\n"
			"online_cpus=%u\n"
			"mem_total_kb=%lu\n"
			"mem_free_kb=%lu\n"
			"kernel_release=%s\n"
			"page_size=%lu\n"
			"hz=%d\n"
			"device_opens=%d\n"
			"device_reads=%d\n",
			(unsigned long long)ktime_get_boottime_seconds(),
			num_online_cpus(),
			(si.totalram * si.mem_unit) >> 10,
			(si.freeram * si.mem_unit) >> 10,
			init_utsname()->release,
			PAGE_SIZE,
			HZ,
			atomic_read(&sm_open_count),
			atomic_read(&sm_read_count));

	ret = simple_read_from_buffer(ubuf, count, ppos, kbuf, len);
	kfree(kbuf);
	return ret;
}

static const struct file_operations sm_fops = {
	.owner = THIS_MODULE,
	.open = sm_open,
	.release = sm_release,
	.read = sm_read,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
static char *sm_devnode(const struct device *dev, umode_t *mode)
#else
static char *sm_devnode(struct device *dev, umode_t *mode)
#endif
{
	if (mode)
		*mode = 0444;	/* read-only for everyone */
	return NULL;
}

static int __init sm_init(void)
{
	struct device *dev;
	int ret;

	ret = alloc_chrdev_region(&sm_devno, 0, 1, DEVICE_NAME);
	if (ret < 0) {
		pr_err("securemon: alloc_chrdev_region failed: %d\n", ret);
		return ret;
	}
	cdev_init(&sm_cdev, &sm_fops);
	sm_cdev.owner = THIS_MODULE;
	ret = cdev_add(&sm_cdev, sm_devno, 1);
	if (ret < 0)
		goto err_region;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	sm_class = class_create(DEVICE_NAME);
#else
	sm_class = class_create(THIS_MODULE, DEVICE_NAME);
#endif
	if (IS_ERR(sm_class)) {
		ret = PTR_ERR(sm_class);
		goto err_cdev;
	}
	sm_class->devnode = sm_devnode;

	dev = device_create(sm_class, NULL, sm_devno, NULL, DEVICE_NAME);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto err_class;
	}
	pr_info("securemon: loaded, major=%d minor=%d -> /dev/%s\n",
		MAJOR(sm_devno), MINOR(sm_devno), DEVICE_NAME);
	return 0;

err_class:
	class_destroy(sm_class);
err_cdev:
	cdev_del(&sm_cdev);
err_region:
	unregister_chrdev_region(sm_devno, 1);
	return ret;
}

static void __exit sm_exit(void)
{
	device_destroy(sm_class, sm_devno);
	class_destroy(sm_class);
	cdev_del(&sm_cdev);
	unregister_chrdev_region(sm_devno, 1);
	pr_info("securemon: unloaded\n");
}

module_init(sm_init);
module_exit(sm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LinSFT Project");
MODULE_DESCRIPTION("LinSFT securemon: character device exposing kernel system statistics");
MODULE_VERSION("1.0");
