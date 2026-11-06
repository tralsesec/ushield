#ifndef USHIELD_UAPI_H
#define USHIELD_UAPI_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

/* Unique 8-bit magic number for µShield ioctl definition */
#define USHIELD_IOC_MAGIC 's'
#define USHIELD_VERSION 0x00010000; // v0.1.0

/* Example control commands */
#define USHIELD_IOC_PING _IO(USHIELD_IOC_MAGIC, 1)
#define USHIELD_IOC_GET_VERSION _IOR(USHIELD_IOC_MAGIC, 2, uint32_t)

/* Ring buffer sizing: 64 KB total telemetry buffer (must be power of 2 for fast masking) */
#define USHIELD_RING_CAPACITY 1024

/* Telemetry Event Types */
typedef enum ushield_event_type {
    USHIELD_EVENT_SYSCALL_EXEC = 1,
    USHIELD_EVENT_SYSCALL_DENY = 2,
    USHIELD_EVENT_PROCESS_SEAL = 3,
} ushield_event_type_t;

/* Single Telemetry Record (Fixed Size: 64 bytes for cache-line alignment) */
struct ushield_event {
    uint64_t timestamp_ns; /* Kernel monotonic timestamp (ktime_get_ns) */
    uint32_t pid;          /* Process ID triggering event */
    uint32_t uid;          /* User ID triggering event */
    uint32_t event_type;   /* ushield_event_type_t */
    uint32_t syscall_nr;   /* Syscall number intercepted */
    uint64_t args[3];      /* Syscall parameters / registers */
    uint8_t action_taken;  /* 0 = ALLOW, 1 = DENY, 2 = LOG */
    uint8_t reserved[7];   /* Padding for strict 64-byte alignment */
};

/* Lockless Ring Buffer Header Layout mapped via mmap */
struct ushield_ring_buffer {
    uint32_t head;     /* Written by Ring 0 (Producer offset) */
    uint32_t tail;     /* Written by Ring 3 (Consumer offset) */
    uint32_t capacity; /* Fixed event capacity (USHIELD_RING_CAPACITY) */
    uint32_t flags;    /* Control flags (e.g., buffer overflow indicators) */
    struct ushield_event events[USHIELD_RING_CAPACITY];
};

#endif // USHIELD_UAPI_H
