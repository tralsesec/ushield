#define pr_fmt(fmt) "[µShield] " fmt

#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "../../include/ushield_uapi.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tralsesec");
MODULE_DESCRIPTION("µShield Ring 0 Sandbox & Telemetry Module");
MODULE_VERSION("0.1");

#define DEVICE_NAME "ushield"
#define CLASS_NAME "ushield_class"

static dev_t dev_num;
static struct cdev ushield_cdev;
static struct class *ushield_class;
static struct device *ushield_device;
static struct ushield_ring_buffer *ring_buf = NULL;

/*
 * Pushes a telemetry event into the lockless ring buffer (Producer)
 */
static void ushield_produce_event(ushield_event_type_t type, uint32_t syscall_nr,
                                  ushield_action_type_t action) {
    if (!ring_buf)
        return;

    // Lockless circular index calculation using bitwise MASK (capacity - 1)
    uint32_t idx = ring_buf->head & (USHIELD_RING_CAPACITY - 1);
    struct ushield_event *ev = &ring_buf->events[idx];

    ev->timestamp_ns = ktime_get_ns();
    ev->pid = current->pid;
    ev->uid = current->cred->uid.val;
    ev->event_type = type;
    ev->syscall_nr = syscall_nr;
    ev->action_taken = action;

    // Ensure memory writes complete before incrementing head (Memory Barrier)
    smp_mb();
    ring_buf->head++;
}

/*
 * VFS .mmap Callback: Maps Ring 0 kernel ring buffer directly to Ring 3 virtual memory.
 */
static int ushield_mmap(struct file *file, struct vm_area_struct *vma) {
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long expected_size = PAGE_ALIGN(sizeof(struct ushield_ring_buffer));

    if (size > expected_size) {
        pr_err("mmap size request (%lu bytes) exceeds allocated ring buffer (%lu bytes)\n", size,
               expected_size);
        return -EINVAL;
    }

    // Convert kernel virtual address to Physical Page Frame Number (PFN)
    unsigned long pfn = virt_to_phys((void *)ring_buf) >> PAGE_SHIFT;

    // Map physical address to user-space virtual memory space
    if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot)) {
        pr_err("remap_pfn_range failed!\n");
        return -EAGAIN;
    }

    pr_info("mmap successfully mapped %lu bytes to PID %d\n", size, current->pid);
    return 0;
}

/*
 * Called when a process opens /dev/ushild.
 * Logs the caller's PID and UID/EUID for Ring 0 auditing.
 */
static int ushield_open(struct inode *inode, struct file *file) {
    const struct cred *cred = current_cred();
    pr_info("/dev/ushild opened by PID %d (UID: %d, EUID: %d)\n", current->pid, cred->uid.val,
            cred->euid.val);

    // Push telemetry event on open
    ushield_produce_event(USHIELD_EVENT_SYSCALL_EXEC, 2, USHIELD_ACTION_ALLOW);
    return 0;
}

/*
 * Called when a process closes its file descriptor to /dev/ushield.
 */
static int ushield_release(struct inode *inode, struct file *file) {
    pr_info("/dev/ushield closed by PID %d", current->pid);
    return 0;
}

/*
 * ioctl Handler: Receives control commands from ushieldd
 */
static long ushield_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
    case USHIELD_IOC_PING:
        pr_info("ioctl PING received from PID %d!\n", current->pid);
        return 0;

    case USHIELD_IOC_GET_VERSION: {
        uint32_t ver = USHIELD_VERSION;
        if (copy_to_user((uint32_t __user *)arg, &ver, sizeof(ver))) {
            return -EFAULT;
        }
        pr_info("ioctl GET_VERSION called by PID %d\n", current->pid);
        return 0;
    }

    default:
        pr_warn("Uknown ioctl command 0x%x from PID %d\n", cmd, current->pid);
        return -ENOTTY; // Standard POSIX error for unknown ioctl.
    }
}

/*
 * Virtual File System (VFS) callback dispatch table.
 */
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = ushield_open,
    .release = ushield_release,
    .unlocked_ioctl = ushield_ioctl,
    .mmap = ushield_mmap,
};

/*
 * Custom udev callback setting /dev/ushield mode to 0666 (rw-rw-rw-),
 * enabling unprivileged user space daemons (ushieldd) to access the node.
 */
static char *ushield_devnode(const struct device *dev, umode_t *mode) {
    if (mode) {
        *mode = 0666;
    }
    return NULL;
}

static int __init ushield_init(void) {
    int ret;

    pr_info("Initializing Ring 0 driver...\n");

    // Step 1: Allocate ring buffer memory
    ring_buf = kmalloc(sizeof(struct ushield_ring_buffer), GFP_KERNEL);
    if (!ring_buf) {
        pr_err("Failed to allocate ring buffer memory\n");
        return -ENOMEM;
    }
    memset(ring_buf, 0, sizeof(struct ushield_ring_buffer));
    ring_buf->capacity = USHIELD_RING_CAPACITY;

    // Step 2: Allocate device numbers
    ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("Failed to allocate major/minor region (err: %d)\n", ret);
        goto fail_free_ring;
    }

    // Step 3: Register cdev
    cdev_init(&ushield_cdev, &fops);
    ushield_cdev.owner = THIS_MODULE;

    ret = cdev_add(&ushield_cdev, dev_num, 1);
    if (ret < 0) {
        pr_err("Failed to add cdev (err: %d)\n", ret);
        goto fail_unregister;
    }

    // Step 4: Create class
    ushield_class = class_create(CLASS_NAME);
    if (IS_ERR(ushield_class)) {
        ret = PTR_ERR(ushield_class);
        pr_err("Failed to create class (err: %d)\n", ret);
        goto fail_cdev;
    }

    ushield_class->devnode = ushield_devnode;

    // Step 5: Create device node
    ushield_device = device_create(ushield_class, NULL, dev_num, NULL, DEVICE_NAME);
    if (IS_ERR(ushield_device)) {
        ret = PTR_ERR(ushield_device);
        pr_err("Failed to create device (err: %d)\n", ret);
        goto fail_class;
    }

    pr_info("Driver registered at /dev/%s (Major: %d, Minor: %d)\n", DEVICE_NAME, MAJOR(dev_num),
            MINOR(dev_num));

    return 0;

/* Error Unwind Chain (Reverse Order) */
fail_class:
    class_destroy(ushield_class);
fail_cdev:
    cdev_del(&ushield_cdev);
fail_unregister:
    unregister_chrdev_region(dev_num, 1);
fail_free_ring:
    kfree(ring_buf);
    return ret;
}

static void __exit ushield_exit(void) {
    device_destroy(ushield_class, dev_num);
    class_destroy(ushield_class);
    cdev_del(&ushield_cdev);
    unregister_chrdev_region(dev_num, 1);

    // Free ring buffer
    if (ring_buf) {
        kfree(ring_buf);
    }

    pr_info("Driver unloaded cleanly from Ring 0\n");
}

module_init(ushield_init);
module_exit(ushield_exit);
