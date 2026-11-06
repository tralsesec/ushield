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
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOG_PREFIX "[µShield] "

__attribute__((format(printf, 1, 2))) static inline void LOG_INFO(const char *fmt, ...) {
    fputs(LOG_PREFIX, stdout);
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
}

__attribute__((format(printf, 1, 2))) static inline void LOG_ERR(const char *fmt, ...) {
    fputs(LOG_PREFIX, stderr);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

static inline void LOG_PERROR(const char *msg) {
    fprintf(stderr, LOG_PREFIX "%s: %s\n", msg, strerror(errno));
}

/*
 * Unprivileged, Self-Sealed HTTP Worker Process (ushieldd-http)
 */
static void run_http_worker(int ipc_fd) {
    LOG_INFO("[ushieldd-http] Worker started (PID %d)\n", getpid());

    // 1. Worker opens /dev/ushield once to self-seal, then closes file descriptor
    int dev_fd = open("/dev/ushield", O_RDWR);
    if (dev_fd >= 0) {
        uint32_t worker_perms = USHIELD_PERM_READ | USHIELD_PERM_WRITE | USHIELD_PERM_NET;
        if (ioctl(dev_fd, USHIELD_IOC_SEAL_SELF, &worker_perms) == 0) {
            LOG_INFO("[ushieldd-http] Worker successfully SELF-SEALED in Ring 0 (Perms: 0x%08X)\n",
                     worker_perms);
        } else {
            LOG_PERROR("[ushieldd-http] Worker self-seal failed");
        }
        close(dev_fd);
    } else {
        LOG_PERROR("[ushieldd-http] Could not open device for self-sealing");
    }

    // 2. Communicate with Master Supervisor strictly over anonymous IPC socketpair
    const char *msg = "REQ_SUPERVISOR_PING";
    LOG_INFO("[ushieldd-http] Sending IPC message to Master Supervisor...\n");
    if (write(ipc_fd, msg, strlen(msg)) < 0) {
        LOG_PERROR("[ushieldd-http] IPC write failed");
    }

    char reply[64] = {0};
    ssize_t bytes = read(ipc_fd, reply, sizeof(reply) - 1);
    if (bytes > 0) {
        LOG_INFO("[ushieldd-http] Received IPC reply from Master: '%s'\n", reply);
    }

    close(ipc_fd);
    LOG_INFO("[ushieldd-http] Worker process exiting cleanly.\n");
    exit(EXIT_SUCCESS);
}

int main(void) {
    LOG_INFO("Initializing µShield Control Daemon Engine (PID %d)...\n", getpid());

    // Create anonymous local IPC channel before fork
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        LOG_PERROR("Failed to create PrivSep socketpair");
        return EXIT_FAILURE;
    }

    pid_t child_pid = fork();
    if (child_pid < 0) {
        LOG_PERROR("Fork failed");
        return EXIT_FAILURE;
    }

    if (child_pid == 0) {
        /* Child Context: ushieldd-http Worker */
        close(sv[0]); // Close Master end of IPC
        run_http_worker(sv[1]);
    }

    /* Parent Context: ushieldd-core Master Supervisor */
    close(sv[1]); // Close Worker end of IPC
    int master_ipc = sv[0];

    LOG_INFO("[ushieldd-core] Master Supervisor initializing (PID %d)...\n", getpid());

    int dev_fd = open("/dev/ushield", O_RDWR);
    if (dev_fd < 0) {
        LOG_PERROR("[ushieldd-core] Failed to open /dev/ushield");
        close(master_ipc);
        return EXIT_FAILURE;
    }

    // 1. Register as Master Supervisor in Ring 0
    if (ioctl(dev_fd, USHIELD_IOC_REGISTER_SUPERVISOR) < 0) {
        LOG_PERROR("[ushieldd-core] Failed to register as Master Supervisor");
        close(dev_fd);
        close(master_ipc);
        return EXIT_FAILURE;
    }

    // 2. Map Telemetry Ring Buffer
    size_t ring_size = sizeof(struct ushield_ring_buffer);
    struct ushield_ring_buffer *ring =
        mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, dev_fd, 0);
    if (ring == MAP_FAILED) {
        LOG_PERROR("[ushieldd-core] Failed to mmap ring buffer");
        close(dev_fd);
        close(master_ipc);
        return EXIT_FAILURE;
    }

    // 3. Handle IPC RPC request from unprivileged Web Worker
    char buf[64] = {0};
    ssize_t bytes = read(master_ipc, buf, sizeof(buf) - 1);
    if (bytes > 0) {
        LOG_INFO("[ushieldd-core] Master received IPC request: '%s'\n", buf);
        const char *ack = "ACK_SUPERVISOR_OK";
        if (write(master_ipc, ack, strlen(ack)) < 0) {
            LOG_PERROR("[ushieldd-core] IPC ack write failed");
        }
    }

    // 4. Wait for Worker to terminate
    int status;
    waitpid(child_pid, &status, 0);

    // 5. Drain pending telemetry events emitted during sealing & open calls
    LOG_INFO("[ushieldd-core] Draining ring buffer events...\n");
    while (ring->tail < ring->head) {
        uint32_t idx = ring->tail & (USHIELD_RING_CAPACITY - 1);
        struct ushield_event *ev = &ring->events[idx];

        LOG_INFO("[EVENT] TS: %lu ns | PID: %u | Type: %u | Syscall: %u | Action: %u\n",
                 (unsigned long)ev->timestamp_ns, ev->pid, ev->event_type, ev->syscall_nr,
                 ev->action_taken);

        ring->tail++;
    }

    munmap(ring, ring_size);
    close(dev_fd);
    close(master_ipc);
    LOG_INFO("[ushieldd-core] PrivSep Master test completed cleanly.\n");
    return EXIT_SUCCESS;
}
