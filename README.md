# LinSFT — Linux Secure File Transfer and System Monitoring Platform

A Linux-only, C++17 secure network file-sharing system: a multi-threaded TCP server with a custom
binary protocol, SQLite metadata, role-based access control, SHA-256 integrity checking, a Qt6
desktop GUI and a full command-line client.

> **Platform:** Ubuntu 24.04 / WSL2 Ubuntu 24.04. **Application language:** C++17 only (build scripts are Bash/CMake).
> **Kernel note:** LinSFT ships an **optional** Linux kernel module, `securemon` (`driver/`). The application works without it; see [driver docs](docs/DRIVER.md). Runtime status of the module is recorded only in `evidence/driver/` after `scripts/vm_verify_driver.sh` has been run on a real Linux VM. See [Linux Device Driver concepts](#5-linux-concepts-used) for what it honestly does instead.

---

## Contents

1. [Project overview](#1-project-overview) · 2. [Features](#2-features) · 3. [Architecture](#3-architecture) · 4. [Technology stack](#4-technology-stack) ·
5. [Linux concepts used](#5-linux-concepts-used) · 6. [Security model](#6-security-model) · 7. [RBAC model](#7-rbac-model) · 8. [Database schema](#8-database-schema) ·
9. [Build instructions](#9-build-instructions) · 10. [Run instructions](#10-run-instructions) · 11. [CLI usage](#11-cli-usage) · 12. [GUI usage](#12-gui-usage) ·
13. [Demo credentials / setup](#13-demo-credentials--setup) · 14. [Testing](#14-testing) · 15. [Troubleshooting](#15-troubleshooting) ·
16. [Limitations](#16-project-limitations) · 17. [Future enhancements](#17-future-enhancements)

More detail: [`docs/SRS.md`](docs/SRS.md), [`docs/SDLC.md`](docs/SDLC.md), [`docs/TestCases.md`](docs/TestCases.md), [`docs/POSTER_COMPLIANCE.md`](docs/POSTER_COMPLIANCE.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/SECURITY.md`](docs/SECURITY.md), [`docs/TESTING.md`](docs/TESTING.md),
[`docs/DEMO.md`](docs/DEMO.md), [`docs/UML.md`](docs/UML.md), [`docs/PRD.md`](docs/PRD.md), [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md).

---

## 1. Project overview

Users register, log in and share files through a server that stores real files on the Linux filesystem and
tracks ownership, checksums, transfers and audit events in SQLite. Every upload and download is verified end-to-end with
SHA-256. What a user can see and do depends on their role (`STUDENT`, `FACULTY`, `ADMIN`), enforced centrally on the server.

## 2. Features

| Area | Implemented and tested |
|---|---|
| Authentication | Register, login, logout, random 256-bit session tokens, idle expiry, brute-force lockout (5 failures → 60 s) |
| RBAC | `ADMIN` / `FACULTY` / `STUDENT`, one central `PermissionService`, role changes apply to live sessions |
| Files | Upload, download, list, search, info (incl. Linux permission bits), rename, delete, share/unshare (private by default) |
| Storage layout | Default `public/ documents/ users/ temporary/`; private per-user home folders (`users.home_directory`); uploads to `public/` auto-shared |
| OOP model | Abstract `User` with `Student` / `Faculty` / `Admin` subclasses (polymorphic `canDelete()`), wired into `PermissionService` |
| Directories | Create, remove (empty only), rename (descendants follow) |
| Administration | List users, change role, delete user (files reassigned), last-admin protection, audit log |
| Monitoring | Per-user transfer history (all users for faculty/admin), audit trail, **System Monitor** (`/proc`, `/sys`, `statvfs`) |
| Integrity | SHA-256 streamed on both ends; mismatch ⇒ file rejected / local copy deleted |
| Networking | TCP, custom binary protocol, thread-per-client, 1 MiB payload cap, 64 KiB chunks, idle timeout, client limit |
| Clients | Qt6 GUI (`network-file-gui`) and CLI (`network-file-client`) – same client library |
| Robustness | `SIGINT`/`SIGTERM` graceful shutdown, no fd/thread/staging-file leaks, stale-transfer recovery on start-up |

## 3. Architecture

```mermaid
flowchart TD
    GUI["Qt6 GUI client<br/>network-file-gui"] --> CL
    CLI["CLI client<br/>network-file-client"] --> CL
    CL["Client library<br/>(framing, SHA-256, chunked transfer)"] -- "TCP · custom binary protocol" --> CM
    subgraph SRV["network-file-server"]
        CM["ConnectionManager<br/>accept loop + thread per client"] --> CH["ConnectionHandler<br/>decode · authenticate · authorise · dispatch"]
        CH --> AUTH["AuthenticationManager<br/>PBKDF2 · sessions · lockout"]
        CH --> PERM["PermissionService / RBAC"]
        CH --> TM["TransferManager<br/>chunked upload / download"]
        CH --> FM["FileManager<br/>virtual FS ↔ real FS"]
        CH --> AUD["Logger / AuditLogger"]
        CH --> SYS["SystemMonitor<br/>/proc · /sys · statvfs"]
        AUTH --> DB[("DatabaseManager<br/>SQLite · prepared statements")]
        TM --> DB
        FM --> DB
        AUD --> DB
        TM --> FS[("Linux filesystem<br/>server_storage/ · mode 0640/0750")]
        FM --> FS
    end
```

**Component diagram** (source layout → CMake targets)

```mermaid
flowchart LR
    common["common/ → linsft_common<br/>crypto · protocol · pathutil · permissions · models"]
    server["server/ → linsft_server_lib<br/>+ network-file-server"]
    client["client/ → linsft_client_lib<br/>+ network-file-client"]
    gui["client/src/gui → linsft_gui_lib<br/>+ network-file-gui"]
    tests["tests/ → test_unit · test_integration<br/>test_gui · test_e2e_cli"]
    common --> server & client
    client --> gui
    server & client & gui --> tests
```

**Upload sequence** (download is symmetric; the client verifies the server-supplied checksum)

```mermaid
sequenceDiagram
    participant C as Client
    participant H as ConnectionHandler
    participant P as PermissionService
    participant T as TransferManager
    participant F as FileManager
    participant D as SQLite
    C->>C: SHA-256 of local file (streamed)
    C->>H: UPLOAD_BEGIN(token, dir, name, size, sha256)
    H->>H: validate token, path, name
    H->>P: has(UPLOAD)?
    H->>T: beginUpload (O_EXCL staging file, transfers row IN_PROGRESS)
    H-->>C: OK(transferId)
    loop 64 KiB chunks
        C->>H: UPLOAD_CHUNK(tid, bytes)
        H->>T: write() + update running SHA-256
    end
    C->>H: UPLOAD_END(tid)
    T->>T: compare SHA-256, fsync
    T->>F: commitUpload (rename(2) + DB upsert in one transaction)
    F->>D: INSERT/UPDATE files
    H->>D: audit_logs row
    H-->>C: OK / CHECKSUM_MISMATCH
```

**Data flow & security flow**

```mermaid
flowchart LR
    R["Request frame"] --> V1{"Header valid?<br/>magic · version · ≤1 MiB"}
    V1 -- no --> X1["BAD_REQUEST + close"]
    V1 -- yes --> V2{"Session token valid?"}
    V2 -- no --> X2["AUTH_REQUIRED"]
    V2 -- yes --> V3{"Path / name valid?<br/>no '..', no control chars"}
    V3 -- no --> X3["INVALID_PATH + audit"]
    V3 -- yes --> V4{"PermissionService:<br/>role + ownership"}
    V4 -- no --> X4["FORBIDDEN + audit DENIED"]
    V4 -- yes --> OP["Operation via prepared statements<br/>+ POSIX I/O (O_NOFOLLOW)"]
    OP --> AUD["Audit log + response"]
```

**Database ER diagram**

```mermaid
erDiagram
    users ||--o{ files : owns
    users ||--o{ directories : owns
    users { int id PK
            text username UK
            text salt
            text pw_hash
            int iterations
            text role
            text home_directory
            int created_at
            int last_login }
    files { int id PK
            text path UK
            text name
            text parent
            int owner_id FK
            int size
            text sha256
            int shared
            int created_at
            int modified_at }
    directories { int id PK
                  text path UK
                  text name
                  text parent
                  int owner_id FK
                  int created_at }
    transfers { int id PK
                int user_id
                text username
                text direction
                text file_path
                int size
                text sha256
                text status
                text detail
                text client_addr
                int started_at
                int finished_at }
    audit_logs { int id PK
                 int ts
                 int user_id
                 text username
                 text action
                 text target
                 text result
                 text client_addr
                 text detail }
```
(`transfers` and `audit_logs` deliberately have no foreign key so history survives user deletion. `directories.owner_id = 0` means "system", used by the four default directories.)

## 4. Technology stack

C++17 (g++ 13) · CMake ≥ 3.16 · POSIX sockets/threads (`std::thread`) · SQLite 3 · Qt 6 Widgets (GUI) · Bash (scripts only).
No third-party crypto library: SHA-256, HMAC and PBKDF2 are implemented in `common/src/crypto.cpp` and verified against NIST/RFC test vectors.

## 5. Linux concepts used

| Concept | Where |
|---|---|
| TCP sockets: `socket/bind/listen/accept4/connect/send/recv`, `getsockname`, `SO_REUSEADDR`, `SO_RCVTIMEO`, `TCP_NODELAY`, `MSG_NOSIGNAL` | `server/src/server.cpp`, `common/src/protocol.cpp`, `client/src/client.cpp` |
| `poll()` accept loop with 200 ms wake-up so shutdown is prompt | `ConnectionManager::run` |
| POSIX file I/O: `open` (`O_EXCL`, `O_NOFOLLOW`, `O_CLOEXEC`), `read`, `write`, `fsync`, `close`, `fstat`, `lseek`, `rename`, `unlink`, `mkdir`, `rmdir` | `TransferManager`, `FileManager` |
| Linux permissions: files `0640`, directories `0750`, DB `0600`, credentials file `0600` | created with explicit modes |
| Threads and synchronisation: thread-per-client, `std::mutex`, `std::recursive_mutex` (DB), per-connection `TransferContext` | `ConnectionManager`, `DatabaseManager`, `FileManager` |
| Signals: `sigaction` for `SIGINT`/`SIGTERM` (graceful stop), `SIGPIPE` ignored | `server/src/main.cpp` |
| Resource cleanup: RAII for fds/statements/transactions; sockets shut down and threads joined on stop | everywhere |
| procfs / sysfs / `statvfs`: `/proc/meminfo`, `/proc/loadavg`, `/proc/uptime`, `/proc/self/status`, `/proc/devices`, `/sys/block/*` | `SystemMonitor` |
| Terminal control: `termios` (no-echo password prompt) | CLI client, `--init-admin` |

### Linux Device Driver concepts — what is real and what is not

* **Optional kernel module `securemon`** (`driver/securemon.c`, `driver/Makefile`): a character device `/dev/securemon` (dynamic major, read-only mode 0444) implementing `open`, `read` and `release` only — no `write`, `ioctl`, procfs or sysfs interface. `read()` returns key=value text (uptime, online CPUs, total/free RAM, kernel release, page size, HZ, open/read counters) produced inside the kernel.
* **Integration:** `SystemMonitor::snapshot()` reads the device on every `SYSINFO` request and shows `securemon ...` lines; if the module is not loaded it shows `securemon driver = not loaded (<reason>)` and everything else works unchanged. Path is configurable (`driver_path` in `config/server.conf`, or `--driver PATH`).
* **Verification status:** loading a module needs a real Linux kernel with matching headers and root; it cannot be done in WSL2's default kernel or a container. Run `sudo scripts/vm_verify_driver.sh` on an Ubuntu VM; results land in `evidence/driver/`. Until that has been run, the driver is *implemented but not runtime-verified*.
* **What LinSFT also does with drivers (from user space, always available):**
  * Reads entropy from the **`/dev/urandom` character device** (`open`/`read`) for salts and session tokens. The System Monitor shows its major/minor numbers and the kernel driver that owns that major, parsed from `/proc/devices`.
  * Enumerates **block devices** through sysfs (`/sys/block/*/size`, `queue/rotational`, `dev`) and maps their major numbers to block drivers via `/proc/devices`.
  * Queries the storage filesystem with `statvfs(2)`.
* Limitations of the module: read-only text interface, no ioctl, one device, not signed (fails to load under Secure Boot unless signed).

## 6. Security model

Summary (full detail in [`docs/SECURITY.md`](docs/SECURITY.md)):

* **Passwords:** random 16-byte salt per user, PBKDF2-HMAC-SHA256 (100 000 iterations), constant-time comparison; plaintext never stored or logged. Unknown users cost the same CPU as wrong passwords.
* **Sessions:** 256-bit random tokens from `/dev/urandom`, validated on *every* request, 30 min idle expiry, revoked on logout / user deletion, role changes take effect immediately.
* **Brute force:** 5 failed logins ⇒ 60 s lockout per username.
* **Path safety:** all paths are virtual, canonicalised and *rejected* if they contain `..`, backslashes, control characters or hidden (`.`-prefixed) names; files are opened with `O_NOFOLLOW`; symlinks planted in storage are never followed.
* **Integrity:** SHA-256 computed by sender and receiver; uploads are staged in `server_storage/.tmp` and only `rename(2)`d into place after the checksum matches.
* **SQL:** every statement is prepared with bound parameters; no string-built SQL with user data (`instr()` replaces `LIKE` so search has no wildcard injection).
* **Protocol:** magic + version check, 1 MiB payload cap, bounds-checked reader, unknown/truncated frames handled without crashing; malformed frames close the connection cleanly.
* **Audit:** logins, logouts, every file operation and every *denied* or *rejected* attempt are written to `audit_logs` and the server log (control characters stripped to prevent log forging).
* **Transport:** plain TCP (no TLS) — see [limitations](#16-project-limitations). The default bind address is `127.0.0.1`.

## 7. RBAC model

| Permission | STUDENT | FACULTY | ADMIN |
|---|:-:|:-:|:-:|
| Login / logout, list, search, info, upload, download (permitted files) | ✔ | ✔ | ✔ |
| Create directories; rename / delete / share **own** files; remove **own** directories | ✔ | ✔ | ✔ |
| Read private files of other users | – | ✔ | ✔ |
| View transfer history of **all** users | – (own only) | ✔ | ✔ |
| System Monitor | – | ✔ | ✔ |
| Rename / delete / share **any** file, remove any directory | – | – | ✔ |
| User management (list, set role, delete), audit log | – | – | ✔ |

*Visibility rule:* a file is readable by its owner, by everyone if the owner marked it **shared**, and by faculty/admin. Files are private by default.
All rules live in `common/src/permissions.cpp` (`PermissionService`); handlers never compare role names themselves. The GUI uses the same table only to **hide** controls the role lacks.

## 8. Database schema

See [`database/schema.sql`](database/schema.sql) (embedded into the server at build time) and the ER diagram above.
Tables: `users`, `files`, `directories`, `transfers`, `audit_logs`.

## 9. Build instructions

Ubuntu 24.04 / WSL2 Ubuntu 24.04 — exact commands:

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config libsqlite3-dev sqlite3 qt6-base-dev
# (WSL2 + Windows 11 / recent Windows 10 includes WSLg, so the GUI works out of the box)

unzip LinSFT-Final.zip && cd LinSFT
mkdir -p build && cd build
cmake ..
make -j$(nproc)
cd ..
```

or simply `./scripts/setup.sh && ./scripts/build.sh`, or `make deps && make` (the `Makefile` is a thin wrapper around CMake; `make test`, `make clean`, `make distclean` also exist). Add `--no-gui` to `build.sh` (or `cmake -DLINSFT_BUILD_GUI=OFF ..`) to build without Qt.
If Qt6 is missing, CMake prints a warning and still builds the server and CLI.
Build output is placed in `build/bin/`, and convenience symlinks `./network-file-server`, `./network-file-client`, `./network-file-gui` are created in the project root.

## 10. Run instructions

```bash
# one-time: create demo accounts (random passwords, saved to config/demo-credentials.txt, mode 0600)
./file_server --seed-demo

# Terminal 1 — server (default port 5000; Ctrl+C stops it gracefully)
./file_server 5000

# Terminal 2 — GUI client
./network-file-gui
# or the guaranteed CLI fallback:
./file_client 127.0.0.1 5000
```

`file_server` / `file_client` are the short names for `network-file-server` / `network-file-client` (both exist after the build, as symlinks in the project root).
`make run-server`, `make run-client`, `make run-gui` and `./scripts/run_demo.sh` do the same from one command.
Server options: `[PORT]`, `--config FILE`, `--port N`, `--bind ADDR`, `--quiet`.
Remote access: set `bind_address = 0.0.0.0` in `config/server.conf` and start clients with the server's IP.

**What the server prints** (poster format; the detailed `AUDIT …` lines go to `logs/server.log` only):

```text
==================================================
          Network File Sharing Server
==================================================
Port     : 5000
Storage  : ./server_storage
Database : database/file_sharing.db
Status   : RUNNING
==================================================
[INFO] Server started. Waiting for clients... (Ctrl+C to stop)
[CLIENT] 127.0.0.1:52310 connected (student1)
[UPLOAD] student1 -> /documents/project.zip (5.1 MiB) SUCCESS
[DOWNLOAD] student1 <- /documents/project.zip (5.1 MiB) SUCCESS
[SEARCH] student1 keyword: project (1 file found)
[DELETE] student1 -> /documents/old.txt SUCCESS
[DENIED] student1 MKDIR /users/other
```

### Storage layout

On first start the server creates these real directories under `server_storage/`:

| Directory | Purpose / rule |
|---|---|
| `public/` | Everything uploaded here is automatically **shared** (readable by all users) |
| `documents/` | General area; files are private to their owner unless shared |
| `users/<name>/` | Each user's **private home** (created at registration/first login, recorded in `users.home_directory`). Only that user or an admin may create/upload inside; `users/` itself is admin-only |
| `temporary/` | Scratch area, writable by everyone |

The four top-level directories are system-owned: ordinary users cannot rename or remove them. The root `/` itself is writable by every user.

## 11. CLI usage

Commands are **case-insensitive** (`LIST`, `list` and `ls` are the same). Start with `./file_client 127.0.0.1 5000`; on a terminal you are prompted for `Username:` / `Password:` (shown as `****`); leave the username blank to skip and use `REGISTER` / `LOGIN` instead.

```text
REGISTER <user>            create a STUDENT account (prompts for password)
LOGIN <user> | LOGOUT | WHOAMI
LIST [path] [-l]  CD <path>  PWD  SEARCH <text>  INFO <path>
UPLOAD <local file> [remote dir] [--shared] [--overwrite]
DOWNLOAD <remote file> [local path] [--overwrite]
RENAME <path> <new name>   DELETE <file>   MKDIR <path>   RMDIR <path>
SHARE <file>   UNSHARE <file>
HISTORY [n]
SYSINFO                                       (FACULTY / ADMIN)
USERS | SETROLE <user> <STUDENT|FACULTY|ADMIN> | DELUSER <user> | AUDIT [n]   (ADMIN)
```

Example session:

```text
$ ./file_client 127.0.0.1 5000
Connected to server 127.0.0.1:5000
Username (blank = skip, use REGISTER/LOGIN later): student1
Password: ********
Login successful! Role: STUDENT

Type 'help' to see available commands.
File> LIST
Server files:
 1. documents/                     <DIR>
 2. public/                        <DIR>
 3. temporary/                     <DIR>
 4. users/                         <DIR>
File> UPLOAD ~/project.zip /documents
Uploading... 100% (5.1 MiB)
Checksum: VERIFIED (SHA-256, confirmed by server)
Upload completed successfully.
File> INFO /documents/project.zip
Path:        /documents/project.zip
Size:        5400000 bytes (5.1 MiB)
SHA-256:     997aee8e...
Permissions: -rw-r----- (0640)
Owner:       student1
```

## 12. GUI usage

`./network-file-gui [--host HOST] [--port PORT]`

1. **Login dialog** — enter server/port, username and password, **Login**; or **Register** to create a STUDENT account (signs you in).
2. **Files tab** — table of files/folders you may see. Double-click a folder to enter it, **Up** to go back, search box + **Search**/**Clear**.
   Buttons: **Upload**, **Download**, **File Info**, **Rename**, **Delete**, **Share / Unshare**, **New Folder**, **Remove Folder**, **Refresh**.
   Buttons are enabled only when the selection and your role allow the action.
3. **Transfer History** tab — your transfers (everyone's for faculty/admin) with status and checksum prefix.
4. **System Monitor** tab *(faculty/admin)* — live server + Linux host metrics.
5. **Users** and **Audit Log** tabs *(admin)* — change role, delete user, review every security event.
6. **Logout** (top-right or *Session* menu) returns to the login dialog.

Every visible control performs a real action; controls your role cannot use are hidden or disabled (verified by `test_gui`).

## 13. Demo credentials / setup

No password is hard-coded anywhere. Choose one of:

| Goal | Command |
|---|---|
| Demo accounts `admin`, `faculty1`, `student1` with **random** passwords | `./network-file-server --seed-demo` → printed once and saved to `config/demo-credentials.txt` (mode 0600, git-ignored). Re-running generates **new** passwords (this is also the *reset* procedure). |
| Create / reset **one** admin with your own password | `./network-file-server --init-admin myadmin` (prompts, no echo). Non-interactive: `LINSFT_ADMIN_PASSWORD='…' ./network-file-server --init-admin myadmin` |
| Normal-user demo | Click **Register** in the GUI (or `register alice` in the CLI) — self-registration always creates a `STUDENT`. |

Run these commands while the server is **stopped** (recommended; a running server keeps its in-memory sessions, so changed credentials only apply to new logins).
Full reset: stop the server, then `make distclean` (or `rm -rf database/*.db* server_storage/* logs/*`) and seed again.

## 14. Testing

```bash
cd build && ctest --output-on-failure        # runs all four suites (GUI suite uses QT_QPA_PLATFORM=offscreen automatically)
```

| Suite | What it proves |
|---|---|
| `test_unit` (18 cases, 256 checks) | SHA-256 / HMAC / PBKDF2 against NIST & RFC vectors, protocol framing, malformed-frame handling over real sockets, path validation, full RBAC matrix, SQLite prepared statements, SQL-injection strings, transactions |
| `test_integration` (27 cases, 624 checks) | A real server on a real TCP port: register/login/logout, token replay/forgery, lockout, upload/download + SHA-256 (empty, odd-size, chunk-aligned files), checksum mismatch, tampered storage, path traversal, symlink planting, ownership & visibility, rename/delete/mkdir/rmdir/search/info, history scoping, admin user management, audit trail, hostile network input, mid-transfer disconnect, 12 concurrent clients, client limit, graceful shutdown, persistence, crash recovery, Unicode names |
| `test_gui` (6 cases, 110 checks) | Real Qt widgets (offscreen): login dialog, every dashboard action against a live server, role-based tab/button visibility, session loss |
| `test_e2e_cli` (58 checks) | The real `network-file-server` and `network-file-client` binaries: admin init, demo seeding, full user flow, faculty/admin features, 6 parallel CLI clients, **SIGINT** shutdown (exit code 0, port closed, no staging files) |

**Latest verification result:** 1,048 automated checks passed, 0 failed (Unit 256 + Integration 624 + GUI 110 + E2E CLI 58).

See [`docs/TESTING.md`](docs/TESTING.md) for the manual test plan and results.

## 15. Troubleshooting

| Symptom | Fix |
|---|---|
| `cmake` says Qt6 not found | `sudo apt install qt6-base-dev`, or build without GUI: `./scripts/build.sh --no-gui` |
| GUI: "could not connect to the display / xcb" | WSL2 needs WSLg (Windows 11 / current Windows 10). Update with `wsl --update` in PowerShell, then `wsl --shutdown`. Use `./network-file-client` meanwhile. |
| `bind 127.0.0.1:5000: Address already in use` | Another server instance is running: `pkill -x network-file-server`, or use another port: `./file_server 5001` and `./file_client 127.0.0.1 5001` |
| Client says *Is network-file-server running?* | Start the server in another terminal; check host/port |
| Login says *too many failed attempts* | Wait 60 s (per-username lockout) |
| `database error` in client | See `logs/server.log`; make sure `database/` is writable |
| Want to start from scratch | Stop the server, run `make distclean`, then `./file_server --seed-demo` again |

## 16. Project limitations

* **No TLS.** Traffic (including passwords) is unencrypted; use only on localhost/trusted networks or tunnel through SSH (`ssh -L 5000:127.0.0.1:5000 host`). TLS is the first item under future work.
* Thread-per-client model (capped by `max_clients`, default 64) — fine for a lab/classroom, not for thousands of connections.
* Sessions are in memory: restarting the server logs everyone out.
* Transfers are not resumable; one request in flight per connection (up to 8 open transfers).
* No quotas. Directory removal requires an empty directory (no recursive delete).
* The GUI performs network calls on the UI thread (it stays responsive during transfers via a progress dialog, but a stalled server blocks the window until the 30 s timeout).
* The optional `securemon` kernel module is implemented but only runtime-verified once `evidence/driver/` has been produced on a real Linux VM (see section 5).

## 17. Future enhancements

TLS (OpenSSL) with certificate pinning · resumable/parallel transfers · epoll worker-pool server · per-user quotas ·
file versioning and trash · two-factor login · persistent sessions · a char-device driver or eBPF probe exporting transfer counters to the System Monitor · Windows-native client.

---

*License: MIT. Layout:* `client/ common/ server/ database/ config/ server_storage/ logs/ tests/ docs/ scripts/ Makefile CMakeLists.txt`
