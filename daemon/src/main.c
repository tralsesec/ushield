#include "../../include/ushield_uapi.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define LOG_PREFIX "[µShield] "

/*
 * Static inline variadic logger for stdout.
 * __attribute__((format(printf, 1, 2))) enforces GCC/Clang type checking on format specifiers.
 */
__attribute__((format(printf, 1, 2))) static inline void LOG_INFO(const char *fmt, ...) {
    fputs(LOG_PREFIX, stdout);
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
}

/*
 * Static inline variadic logger for stderr.
 */
__attribute__((format(printf, 1, 2))) static inline void LOG_ERR(const char *fmt, ...) {
    fputs(LOG_PREFIX, stderr);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

/*
 * Logger for system call failures (equivalent to perror).
 */
static inline void LOG_PERROR(const char *msg) {
    fprintf(stderr, LOG_PREFIX "%s: %s\n", msg, strerror(errno));
}

int main(void) {
    LOG_INFO("Opening /dev/ushield...\n");

    int fd = open("/dev/ushield", O_RDWR);
    if (fd < 0) {
        LOG_PERROR("Failed to open /dev/ushield");
        return EXIT_FAILURE;
    }

    LOG_INFO("Successfully opened device (fd: %d)\n", fd);

    // 1. Send PING ioctl
    LOG_INFO("Sending USHIELD_IOC_PING...\n");
    if (ioctl(fd, USHIELD_IOC_PING) < 0) {
        LOG_PERROR("PING ioctl failed");
        goto failed;
    }

    // 2. Fetch Driver Version via ioctl
    uint32_t version = 0;
    LOG_INFO("Fetching driver version via USHIELD_IOC_GET_VERSION...\n");
    if (ioctl(fd, USHIELD_IOC_GET_VERSION, &version) < 0) {
        LOG_PERROR("GET_VERSION ioctl failed");
        goto failed;
    }

    uint8_t major = (version >> 16) & 0xFF;
    uint8_t minor = (version >> 8) & 0xFF;
    uint8_t patch = version & 0xFF;

    LOG_INFO("Received Driver Version: v%d.%d.%d (0x%08X)\n", major, minor, patch, version);

    size_t ring_size = sizeof(struct ushield_ring_buffer);
    struct ushield_ring_buffer *ring =
        mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (ring == MAP_FAILED) {
        LOG_PERROR("Failed to mmap ring buffer");
        goto failed;
    }

    LOG_INFO("Successfully mapped Ring Buffer at %p (Capacity: %u events)\n", (void *)ring,
             ring->capacity);

    // Poll events off the ring buffer (Consumer)
    while (ring->tail < ring->head) {
        uint32_t idx = ring->tail & (USHIELD_RING_CAPACITY - 1);
        struct ushield_event *ev = &ring->events[idx];

        LOG_INFO("[EVENT] TS: %lu ns | PID: %u | Syscall: %u | Action: %u\n", ev->timestamp_ns,
                 ev->pid, ev->syscall_nr, ev->action_taken);

        ring->tail++;
    }

    // Clean up mapping before exit
    munmap(ring, ring_size);

    close(fd);
    LOG_INFO("Test completed cleanly.\n");
    return EXIT_SUCCESS;

failed:
    close(fd);
    return EXIT_FAILURE;
}
