# µShield (ushield)

> *Status: Work In Progress (WIP) — Active Pre-v0.1 Development*

**µShield** is an ultra-lightweight, high-performance sandbox and security telemetry engine written in pure C (C11). Designed to bypass heavy container runtime stacks like Docker or containerd, µShield relies on direct cooperation between a privilege-separated user-space controller (`ushieldd`) and a custom Ring 0 Linux Kernel Module (`ushield.ko`) powered by eBPF LSM hooks.

---

## Architecture Overview

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ USERSPACE (ushieldd - Privilege-Separated Control Engine)               │
│                                                                         │
│  ┌─────────────────────────────┐         ┌───────────────────────────┐  │
│  │ ushieldd-http (Web UI)      │         │ ushieldd-core (Master)    │  │
│  │ • Unprivileged (UID 1000)   │  socket │ • Master Supervisor (UID 0)  │
│  │ • Self-Sealed (No /dev access)◄pair──►│ • Handles /dev/ushield    │  │
│  │ • Exposes HTTP / API        │   IPC   │ • Issues Kernel ioctls    │  │
│  └─────────────────────────────┘         └─────────────┬─────────────┘  │
└────────────────────────────────────────────────────────┼────────────────┘
                                                         │ /dev/ushield
┌────────────────────────────────────────────────────────┴────────────────┐
│ KERNELSPACE (ushield.ko - Ring 0 Privileged Control Plane)              │
│                                                                         │
│  • Master Supervisor Registration (USHIELD_IOC_REGISTER_SUPERVISOR)     │
│  • Creator-Scoped Identity & Process Hierarchy Registry                 │
│  • Lockless Zero-Copy Telemetry Streaming (mmap Ring Buffer)            │
│  • Granular Syscall Permission Bitmasks (READ, WRITE, EXEC, NET, PROC)  │
│  • Pre-Exec Child Sealing (First-Instruction Lock Down)                 │
│  • Real-Time Syscall Interception & Enforcement via eBPF LSM            │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Key Technical Specifications

### 1. Privilege-Separated User-Space Controller (`ushieldd`)

* **Zero External Dependencies:** Statically linked C11 binary.
* **Privilege Separation (PrivSep):** The daemon splits into two isolated execution contexts upon launch:
    1. **`ushieldd-core` (Master Supervisor):** Runs as `root` (UID 0), registers with `ushield.ko`, retains exclusive administrative access to `/dev/ushield`, and acts as an internal RPC router.
    2. **`ushieldd-http` (API/Web UI Worker):** Spawns via `fork()`, drops privileges to an unprivileged user (`nobody`/`uid 1000`), closes `/dev/ushield` descriptors, and self-seals via `USHIELD_IOC_SEAL_SELF`.
* **Isolated Control IPC:** `ushieldd-http` communicates with `ushieldd-core` strictly across an anonymous `AF_UNIX` `socketpair` IPC bridge. An RCE in the Web stack cannot issue `ioctl` commands or tamper with Ring 0.
* **Embedded Control Plane:** Embedded Single-Page Web UI served directly from C bytecode. Simple file-based configuration via `ushield.conf`.

### 2. Micro-Container & Asymmetric Namespace Isolation

* **Asymmetric Visibility:** Target binaries execute within hyper-restricted, custom Linux namespaces (`CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWNS`).
* **Target View:** Fully configurable process illusion, presenting execution environments as stripped-down bare kernels or full, standard Linux servers via custom `rootfs` profiles.
* **Controller View:** `ushieldd-core` retains top-down supervisor visibility into containerized processes for real-time monitoring, signal handling, and telemetry streaming.

### 3. Ring 0 Kernel Driver & Telemetry (`ushield.ko`)

* **Zero-Copy IPC Telemetry:** Direct `/dev/ushield` character device offering contiguous `mmap` ring buffers for lockless, nanosecond telemetry streaming directly into user space.
* **Master Supervisor Security:** `USHIELD_IOC_REGISTER_SUPERVISOR` locks administrative capabilities to the verified master daemon PID.
* **Granular Category Sealing:** Replaces blanket locks with bitmask permission profiles:
    1. `USHIELD_PERM_READ`: File read operations.
    2. `USHIELD_PERM_WRITE`: File write operations.
    3. `USHIELD_PERM_EXEC`: Binary execution (`execve`).
    4. `USHIELD_PERM_NET`: Network socket creation, binding, and connecting.
    5. `USHIELD_PERM_PROCESS`: Process lifecycle management (`fork`/`clone`).
* **Creator-Scoped Access Control:** Ring 0 identity registry enforces an access matrix based on process hierarchy (`task_struct->real_parent`), ensuring target policies are accessible only by the process itself, its creator PID, or the Master Supervisor.
* **Pre-Exec Child Sealing:** Enforces sandbox policies before a child process executes its first assembly instruction (`_start`), eliminating TOCTOU race conditions during startup.

---

## API & Control Capabilities

The REST API (and matching Web UI) exposes operational control over the engine:

| Endpoint Group | Description |
| --- | --- |
| **`POST /api/auth/login`** | Authenticates against `ushield.conf` creds; returns a session token. |
| **`POST /api/binary/upload`** | Uploads target ELF binaries for sandbox execution. |
| **`GET /api/binary/download`** | Retrieves stored binaries or execution artifacts. |
| **`POST /api/sandbox/create`** | Configures permission bitmasks, namespace masks, and mount points. |
| **`POST /api/sandbox/execute`** | Spawns sandboxed execution with pre-exec sealing and real-time telemetry streaming. |
| **`GET /api/telemetry/stats`** | Fetches low-latency ring buffer metrics and intercepted syscall logs. |
| **`WS /api/sandbox/attach`** | Interactive real-time stream directly into running sandboxes. |

---

## Development Roadmap & Future Architecture

* [x] **Phase 0:** Project layout, Makefile build system, and isolated QEMU/KVM dev VM setup.
* [x] **Phase 1:** Core LKM skeleton (`ushield.ko`) & character device registration (`/dev/ushield`).
* [ ] **Phase 2:** Bare-metal C daemon (`ushieldd`), `ushield.conf` parser, and embedded Web UI.
* [x] **Phase 3:** Zero-copy `mmap` ring buffer telemetry transport.
* [x] **Phase 4:** PrivSep daemon split, process hierarchy identity registry, and granular process sealing (`USHIELD_IOC_SEAL_SELF`, `USHIELD_IOC_REGISTER_TARGET`).
* [ ] **Phase 5:** eBPF LSM syscall filtering (Category rules & explicit whitelists/blacklists).
* [ ] **Phase 6 (Future):** *Behavioral Sequence Filtering* — Advanced workflow state machines in Ring 0 to evaluate execution sequences (e.g., allow `sys_A`, but terminate if followed immediately by `sys_B`).
* [ ] **Phase 7 (Future):** HTTP library replaced by [`asmhttp`](https://github.com/tralsesec/asmhttp) when ready for production.

---

## License

Developed under GPL-2.0 (Kernel Module) and MIT (User-space Daemon).
