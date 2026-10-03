# Architecture

See the diagrams in the [README](../README.md#3-architecture). This document explains responsibilities and design decisions.

## Layers and responsibilities
| Component | File(s) | Responsibility |
|---|---|---|
| Client library | `client/src/client.cpp` | Connect, frame requests, stream files in chunks, compute SHA-256, atomic local save (`.part` → `rename`) |
| CLI / GUI | `cli_main.cpp`, `gui/*` | Presentation only; all behaviour goes through `linsft::Client` |
| ConnectionManager | `server/src/server.cpp` | `poll()` accept loop, thread-per-client, client cap, reaping, graceful stop |
| ConnectionHandler | `connection_handler.cpp` | One thread per connection: decode → authenticate → validate → **authorise** → delegate → audit → reply |
| AuthenticationManager | `auth.cpp` | Registration, PBKDF2 hashing, sessions, lockout |
| PermissionService | `common/src/permissions.cpp` | The *only* place role/ownership rules exist |
| FileManager | `file_manager.cpp` | Virtual tree ↔ real directories; metadata in SQLite; compound operations serialised by a mutex |
| TransferManager | `transfer_manager.cpp` | Upload/download state machines, staging files, running SHA-256, transfer history rows |
| Logger / AuditLogger | `logger.cpp` | Thread-safe `O_APPEND` log; DB audit trail |
| DatabaseManager | `database.cpp` | RAII SQLite wrapper; prepared statements only; `Transaction` guard |
| SystemMonitor | `system_monitor.cpp` | procfs / sysfs / `statvfs` snapshot |

## Wire protocol
16-byte big-endian header (`LSFT` magic, version, type, request id, payload length) + payload built from length-prefixed fields.
Responses echo the request id and type | `0x8000`, and start with `u16 status` + `string message`. Maximum payload 1 MiB; file data moves in 64 KiB chunks.
Every request except `PING`, `REGISTER`, `LOGIN` begins with the session token.

## Storage model
* Virtual absolute paths (`/docs/report.pdf`) map 1:1 to `server_storage/docs/report.pdf`. Directories are real directories (`0750`), files are real files (`0640`).
* Uploads are written to `server_storage/.tmp/up-<random>` (`O_EXCL|O_NOFOLLOW`), hashed while written, verified, `fsync`'d, then published with `rename(2)` inside a DB transaction. `.`-prefixed names are rejected so users can never address `.tmp`.
* On start-up, stale staging files are removed and `IN_PROGRESS` transfer rows are marked `FAILED`.

## Concurrency model
* One accept thread + one thread per client. Shared state: the SQLite connection (serialised by a recursive mutex; `FULLMUTEX` as well), the session map (mutex), `FileManager` compound operations (mutex), counters (`std::atomic`).
* Lesson learned during testing: `INSERT` + `last_insert_rowid()` as two calls raced across threads; `DatabaseManager::insert()` now does both under one lock (regression caught by `concurrent_clients`).
* Shutdown: `stop()` clears the running flag → accept loop exits → every client socket gets `shutdown(SHUT_RDWR)` (wakes threads blocked in `recv`) → threads are joined → `TransferContext` destructors close descriptors, delete staging files and mark transfers `ABORTED`.

## Linux device-driver relationship (honest statement)
LinSFT is a user-space application. It touches kernel drivers only through their user-visible interfaces:
`/dev/urandom` (char device, driver "mem"), `/sys/block/*` and `/proc/devices` (block devices and their registered drivers), `statvfs` (filesystem driver).
An optional kernel module, `securemon` (`driver/`), adds a character device `/dev/securemon`. `SystemMonitor::snapshot()` reads it through the same interface and shows "not loaded" when it is absent, so the rest of the architecture is unchanged.

Data flow: `CLI/GUI client -> SYSINFO request -> ConnectionHandler -> SystemMonitor::snapshot() -> readSecuremon() -> open/read /dev/securemon -> securemon.ko (kernel) -> kernel totals (si_meminfo, num_online_cpus, uptime, utsname)`.

## Software / hardware architecture notes
Layered client–server design with a thin protocol boundary; the server is I/O bound (disk + network), so thread-per-client is adequate. Chunking bounds memory per transfer to 64 KiB regardless of file size, and `fsync` before publish gives durability against power loss.

## Storage layout and home directories
On start-up `FileManager::ensureDefaultLayout()` creates four system-owned directories (`owner_id = 0`): `/public`, `/documents`, `/users`, `/temporary`.
`/users/<name>` is each account's private home; it is created at registration and at login (idempotent) and recorded in `users.home_directory`.
Rules (all in `PermissionService`, none in handlers):
* `canWriteInto(path)`: `/users` is admin-only; `/users/<name>/…` only that user or an admin; everything else is open to all roles.
* `isPublicPath(path)`: uploads under `/public` are stored with `shared = 1`.
* Ownership rules (rename/delete/share/rmdir) still apply, so system directories can only be removed or renamed by an admin.

## Object-oriented user model
`common/include/linsft/user.h`: abstract `User` (`id`, `username`, `role`, `login()`, `logout()`, pure virtual `canDelete(ownerId)`) with `Student`, `Faculty` and `Admin`.
`User::create(Principal)` is a factory; `PermissionService::canDeleteFile()` delegates to it, and a unit test asserts both views always agree.
