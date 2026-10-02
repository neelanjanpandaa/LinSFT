# Product Requirements Document — LinSFT

## 1. Purpose
A Linux-only secure file-sharing platform for an academic setting (students, faculty, administrators), built in C++17 to demonstrate
Linux system programming: sockets, threads, POSIX file I/O, signals, filesystem permissions and process/resource management.

## 2. Users and roles
| Role | Description |
|---|---|
| STUDENT | Default role on self-registration. Manages own files, reads shared files. |
| FACULTY | Student rights + reads all files, sees all transfer history, System Monitor. |
| ADMIN | Everything, plus user management and audit access. Created only through the server's `--init-admin` / `--seed-demo` commands or by another admin. |

## 3. Functional requirements
| ID | Requirement | Status |
|---|---|---|
| FR-1 | Register, login, logout with session tokens | Done, tested |
| FR-2 | Role-based access control (3 roles) centralised in one service | Done, tested |
| FR-3 | Upload / download of binary files in chunks with SHA-256 verification | Done, tested |
| FR-4 | List, search (by name), info, rename, delete files | Done, tested |
| FR-5 | Create / remove / rename directories | Done, tested |
| FR-6 | Share / unshare files; private by default | Done, tested |
| FR-7 | Transfer history (own; all for faculty/admin) | Done, tested |
| FR-8 | Audit log of auth + file operations + denied attempts | Done, tested |
| FR-9 | Admin: list users, change role, delete user | Done, tested |
| FR-10 | System monitoring panel from procfs/sysfs | Done, tested |
| FR-11 | Multi-client concurrency | Done, tested (12 concurrent clients) |
| FR-12 | Qt6 GUI and CLI client | Done, tested |
| FR-13 | Graceful shutdown on SIGINT/SIGTERM | Done, tested |
| FR-14 | Default storage layout (`public`, `documents`, `users`, `temporary`) and private per-user home directories | Done, tested |
| FR-15 | Files uploaded to `/public` are auto-shared; foreign homes are write-protected | Done, tested |
| FR-16 | File info shows Linux permission bits | Done, tested |
| FR-17 | Abstract `User` with `Student`/`Faculty`/`Admin` (polymorphic `canDelete()`) | Done, tested |
| FR-18 | Console activity log (`[CLIENT] [UPLOAD] [DOWNLOAD] [SEARCH] [DELETE] [DENIED]`) and startup banner | Done, tested |

## 4. Non-functional requirements
Security (see `SECURITY.md`), Linux-only, C++17, builds with plain CMake, no network access needed at run time, deterministic automated tests,
protocol payload cap 1 MiB, files never fully loaded into memory (64 KiB chunks), documented demo procedure.

## 5. Out of scope
TLS transport, kernel modules, resumable transfers, quotas, web UI.

## 6. Success criteria
`cmake && make` succeeds from a clean tree, `ctest` passes, and the 5–10 minute demo in `DEMO.md` can be performed by one person.
