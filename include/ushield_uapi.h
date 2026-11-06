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

/* IOCTL Command Definitions */
#define USHIELD_IOC_PING _IO(USHIELD_IOC_MAGIC, 1)
#define USHIELD_IOC_GET_VERSION _IOR(USHIELD_IOC_MAGIC, 2, uint32_t)
#define USHIELD_IOC_REGISTER_SUPERVISOR _IO(USHIELD_IOC_MAGIC, 3)
#define USHIELD_IOC_SEAL_SELF _IOW(USHIELD_IOC_MAGIC, 4, uint32_t)
#define USHIELD_IOC_SEAL_TARGET _IOW(USHIELD_IOC_MAGIC, 5, struct ushield_seal_config)
#define USHIELD_IOC_GET_POLICY _IOWR(USHIELD_IOC_MAGIC, 6, struct ushield_seal_config)

/* Permission Categories */
#define USHIELD_PERM_NONE 0x00000000U
#define USHIELD_PERM_READ (1U << 0)    /* File read operations */
#define USHIELD_PERM_WRITE (1U << 1)   /* File write operations */
#define USHIELD_PERM_EXEC (1U << 2)    /* Binary execution (execve) */
#define USHIELD_PERM_NET (1U << 3)     /* Network socket operations */
#define USHIELD_PERM_PROCESS (1U << 4) /* Process lifecycle (fork/clone) */
#define USHIELD_PERM_ALL 0xFFFFFFFFU

/* Target Seal Configuration Payload */
struct ushield_seal_config {
    uint32_t target_pid;  /* PID to seal */
    uint32_t permissions; /* Allowed USHIELD_PERM_* mask */
    uint32_t flags;       /* Mode flags */
};

/* Telemetry Ring Buffer Definitions */
#define USHIELD_RING_CAPACITY 1024

typedef enum ushield_event_type {
    USHIELD_EVENT_SYSCALL_EXEC = 1,
    USHIELD_EVENT_SYSCALL_DENY = 2,
    USHIELD_EVENT_PROCESS_SEAL = 3,
} ushield_event_type_t;

struct ushield_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t uid;
    uint32_t event_type;
    uint32_t syscall_nr;
    uint64_t args[3];
    uint8_t action_taken;
    uint8_t reserved[7];
};

struct ushield_ring_buffer {
    uint32_t head;
    uint32_t tail;
    uint32_t capacity;
    uint32_t flags;
    struct ushield_event events[USHIELD_RING_CAPACITY];
};

#endif // USHIELD_UAPI_H
