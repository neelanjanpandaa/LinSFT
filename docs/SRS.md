# Software Requirements Specification — LinSFT (Network File Sharing System)

## 1. Introduction
**Purpose.** This document specifies the requirements of LinSFT, a multi-client, TCP-based, Linux-only file sharing system written in C++17.
**Scope.** A server stores files on the Linux filesystem and metadata in SQLite; clients (Qt6 GUI and CLI) authenticate and manage files according to a role (STUDENT, FACULTY, ADMIN).
**Definitions.** *Virtual path*: an absolute path inside the shared storage (`/documents/a.txt`). *Shared file*: readable by every authenticated user. *Home directory*: `/users/<name>`, private to its owner.
**References.** `PRD.md` (product view), `ARCHITECTURE.md`, `SECURITY.md`, `TestCases.md`.

## 2. Overall description
* **Product perspective.** Client–server. One server process, many clients over TCP (default port 5000). Storage: `server_storage/`. Database: `database/file_sharing.db`.
* **User classes.** Student (default), Faculty, Admin — see the RBAC table in the README.
* **Operating environment.** Ubuntu 24.04 / WSL2; g++ ≥ 13, CMake ≥ 3.16, SQLite 3, Qt 6 (optional, GUI only).
* **Constraints.** C++17 only for application code; POSIX APIs; kernel module optional (`securemon`, see DRIVER.md); no external crypto library.
* **Assumptions.** Trusted network or SSH tunnel (no TLS).

## 3. Functional requirements
| ID | Requirement |
|---|---|
| SRS-AUTH-1 | The system shall register users with a unique, case-insensitive username (3–32 characters, starting alphanumeric) and a password of 8–128 characters; self-registration yields role STUDENT. |
| SRS-AUTH-2 | The system shall authenticate users and issue a 256-bit random session token; every request except PING/REGISTER/LOGIN shall carry a valid token. |
| SRS-AUTH-3 | Passwords shall be stored only as salted PBKDF2-HMAC-SHA256 hashes. |
| SRS-AUTH-4 | After 5 consecutive failed logins for a username the system shall refuse logins for that name for 60 s. |
| SRS-AUTH-5 | Sessions shall expire after 30 min idle and be revoked on logout or user deletion. |
| SRS-RBAC-1 | All authorisation decisions shall be taken by `PermissionService` using role and ownership; role changes shall affect live sessions immediately. |
| SRS-RBAC-2 | Students: own files and shared files; Faculty: additionally read all files, all history, system monitor; Admin: additionally manage any file, users, audit log. |
| SRS-RBAC-3 | The model shall be expressed as an abstract `User` with Student/Faculty/Admin subclasses implementing `canDelete()`. |
| SRS-FILE-1 | The system shall upload files in chunks of ≤ 64 KiB without loading whole files into memory, verify SHA-256, and publish atomically only on success. |
| SRS-FILE-2 | The system shall download files in chunks; the client shall verify the server-supplied SHA-256 and discard mismatching data. |
| SRS-FILE-3 | The system shall list, search (case-insensitive name substring across the whole tree, honouring visibility), show information (size, type, owner, SHA-256, shared flag, **Linux permission bits**, created/modified times), rename and delete files. |
| SRS-FILE-4 | Files shall be private by default; owners may share/unshare; files uploaded under `/public` are shared automatically. |
| SRS-DIR-1 | The system shall create, rename and remove (empty) directories as real Linux directories. |
| SRS-DIR-2 | The default layout `/public /documents /users /temporary` shall exist; `/users/<name>` shall be created for every user and be writable only by its owner or an admin. |
| SRS-HIST-1 | Every upload/download shall be recorded (user, direction, path, size, SHA-256, status, times); students see their own, faculty/admin all. |
| SRS-AUD-1 | Logins, logouts, file operations, searches and every denied/rejected request shall be written to `audit_logs` and the server log. |
| SRS-ADM-1 | Admins shall list users, change roles, delete users (their files are reassigned to the acting admin); the last admin shall not be demoted or deleted. |
| SRS-MON-1 | Faculty/admin shall see server statistics and Linux host metrics (procfs, sysfs, statvfs). |
| SRS-NET-1 | The server shall serve multiple concurrent clients (thread per client, configurable limit) using a custom binary protocol with a 1 MiB payload limit. |
| SRS-NET-2 | The server shall shut down gracefully on SIGINT/SIGTERM: stop accepting, close client sockets, join threads, delete staging files, mark open transfers ABORTED. |
| SRS-UI-1 | A Qt6 GUI and a CLI shall expose every operation allowed to the user's role; controls the role lacks shall be hidden or disabled. |
| SRS-UI-2 | The CLI shall accept case-insensitive commands, prompt for Username/Password (masked), and print `Checksum: VERIFIED` after transfers. |
| SRS-OPS-1 | The server shall print a start-up banner and one console line per client connect, upload, download, search, delete and denied request. |
| SRS-OPS-2 | Admin accounts shall be creatable/resettable only through `--init-admin` or `--seed-demo` (no hard-coded credentials). |

## 4. External interfaces
* **User interfaces:** `network-file-gui` (Qt6), `network-file-client` / `file_client` (terminal).
* **Software interfaces:** SQLite 3 C API (prepared statements); POSIX (`socket`, `open`, `read`, `write`, `fsync`, `rename`, `mkdir`, `rmdir`, `unlink`, `stat`, `fstat`, `statvfs`, `opendir`, `readdir`, `sigaction`).
* **Communications interface:** TCP; 16-byte header (`LSFT`, version, type, request id, length) + length-prefixed fields (see `ARCHITECTURE.md`).

## 5. Non-functional requirements
Security (`SECURITY.md`), robustness against malformed input (no crash, clean close), clean build with no warnings, reproducible automated tests, documentation sufficient for a 5–10 minute demo.

## 6. Traceability
Each requirement above is covered by at least one automated test; the mapping is in `TestCases.md`.
