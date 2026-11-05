# µShield (ushield)

> *Status: Work In Progress (WIP) — Active Pre-v0.1 Development*

**µShield** is an ultra-lightweight, high-performance sandbox and security telemetry engine written in pure C (C11). Designed to bypass heavy container runtime stacks like Docker or containerd, µShield relies on direct cooperation between a minimal user-space controller (`ushieldd`) and a custom Ring 0 Linux Kernel Module (`ushield.ko`) powered by eBPF LSM hooks.

---

## Architecture Overview

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ USERSPACE (ushieldd - Pure C11 Static Binary, ~2MB)                     │
│                                                                         │
│  [ ushield.conf ] ──► [ HTTP/REST API + Embedded Web UI ]               │
│                            │ (Upload, Management, Live Streaming)       │
│                            └── Task Router & Namespace Controller       │
└────────────────────────────┼────────────────────────────────────────────┘
                             │  /dev/ushield (Zero-Copy mmap Ring Buffer)
                             │  Custom Syscalls (e.g., sys_shield_seal)
┌────────────────────────────┴────────────────────────────────────────────┘
│ KERNELSPACE (ushield.ko - LKM + eBPF LSM in Ring 0)                     │
│                                                                         │
│  [ Custom Syscalls ] ──► Atomic Nanosecond Process Seal                 │
│  [ eBPF LSM Hooks ]  ──► Dynamic Syscall Whitelisting / Blacklisting    │
│  [ Ring Buffer ]     ──► Zero-Copy Telemetry Stream via Shared Memory   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Key Technical Specifications

### 1. Minimalist User-Space Controller (`ushieldd`)

* **Zero External Dependencies:** Statistically linked C11 binary.
* **Embedded Control Plane:** HTTP/REST API server delivering an embedded Single-Page Web UI directly from C bytecode.
* **Zero-DB Architecture:** Simple file-based configuration via `ushield.conf`. Authentication uses single-tenant admin credentials yielding high-entropy, randomly generated session tokens.
* **Full Process & Binary Lifecycle:** Upload targets, download binaries/artifacts, configure sandboxes, stream analysis logs, and interact with live execution streams.

### 2. Micro-Container & Asymmetric Namespace Isolation

* **Asymmetric Visibility:** Target binaries execute within hyper-restricted, custom Linux namespaces (`CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWNS`).
* **Target View:** To the isolated binary, the environment appears as a completely stripped-down bare kernel—incapable of seeing system binaries (e.g., `/bin/sh` or host tooling).
* **Controller View:** `ushieldd` retains top-down root visibility into the containerized process, allowing real-time command injection, dynamic memory manipulation, and direct kernel module debugging.

### 3. Ring 0 Kernel Driver & Telemetry (`ushield.ko`)

* **Shared Memory Inter-Process Communication (IPC):** Direct `/dev/ushield` character device offering `mmap` ring buffers for zero-copy, nanosecond telemetry streaming into user space.
* **Instant Process Seal:** Custom atomic kernel call (`sys_shield_seal`) forcing nanosecond process locks without POSIX overhead.
* **eBPF Syscall Filtering:** Real-time enforcement using Ring 0 LSM hooks:
* **Granular Whitelisting/Blacklisting:** Block or allow specific syscall IDs.
* **Preset Categories:** Quick rule application (e.g., `ALLOW_NET`, `DISALLOW_FS`, `RESTRICT_EXEC`).

---

## API & Control Capabilities

The REST API (and matching Web UI) exposes full operational control over the engine:

| Endpoint Group | Description |
| --- | --- |
| **`POST /api/auth/login`** | Authenticates against `ushield.conf` creds; returns a session token. |
| **`POST /api/binary/upload`** | Uploads target ELF binaries for sandbox execution. |
| **`GET /api/binary/download`** | Retrieves stored binaries or execution artifacts. |
| **`POST /api/sandbox/create`** | Configures namespace masks, mounts, and syscall filter rules. |
| **`POST /api/sandbox/execute`** | Spawns and seals target execution with real-time telemetry streaming. |
| **`GET /api/telemetry/stats`** | Fetches low-latency eBPF telemetry metrics and syscall logs. |
| **`WS /api/sandbox/attach`** | Interactive real-time shell / stream directly into running sandboxes. |

---

## Development Roadmap & Future Architecture

* [x] **Phase 0:** Project layout, Makefile build system, and isolated QEMU/KVM dev VM setup.
* [ ] **Phase 1:** Bare-metal C daemon (`ushieldd`), `ushield.conf` parser, and embedded Web UI.
* [ ] **Phase 2:** Core LKM skeleton (`ushield.ko`) & character device registration (`/dev/ushield`).
* [ ] **Phase 3:** Zero-copy `mmap` ring buffer telemetry transport.
* [ ] **Phase 4:** Asymmetric namespace isolation engine & `sys_shield_seal` implementation.
* [ ] **Phase 5:** eBPF LSM syscall filtering (Category rules & explicit whitelists/blacklists).
* [ ] **Phase 6 (Future):** *Behavioral Sequence Filtering* — Advanced workflow state machines in Ring 0 to evaluate execution sequences (e.g., allow `sys_A`, but terminate if followed immediately by `sys_B`).
* [ ] **Phase 7 (Future):** Use [`asmhttp`](https://github.com/tralsesec/asmhttp) as http library when it is ready for production.

---

## License

Developed under GPL-2.0 (Kernel Module) and MIT (User-space Daemon).
