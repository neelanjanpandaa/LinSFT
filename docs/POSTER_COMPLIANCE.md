# Poster compliance — "Network File Sharing System" (TCP | Linux | File Operations | C++)

Status: **✔ implemented and tested**, **◐ implemented with a documented difference**.
Nothing on the poster is missing; the remaining differences are naming/structure choices explained below.

| Poster section | Item | Status | Where / evidence |
|---|---|---|---|
| Objective, 1 Overview | Multi-client TCP server, auth, upload/download/list/search/dirs, history in SQLite, multithreading, Linux file ops, OOP | ✔ | whole project; `concurrent_clients` |
| 2 Architecture | Clients (Student/Faculty/Admin) → TCP → Linux file server → shared storage + SQLite | ✔ | `docs/ARCHITECTURE.md` |
| 2 Architecture | Storage `public/ documents/ users/ temporary/` | ✔ | created at start-up under `server_storage/`; `default_layout_home_dirs_and_write_rules` |
| 2 Architecture | `file_sharing.db` | ✔ | default `database/file_sharing.db` (matches the poster's `database/` folder) |
| 3 Key features | Authentication (Admin/Faculty/Student) | ✔ | `AuthenticationManager`; `registration_login_logout` |
| | Chunked upload/download + SHA-256 | ✔ | 64 KiB chunks; `upload_download_roundtrip_sha256` |
| | File management (list, delete, rename, create/remove dir) | ✔ | `FileManager`; `directories_rename_search_info_delete` |
| | Recursive search | ✔ | name search across the whole tree; `SEARCH` |
| | File information: size, type, **permissions**, modified time | ✔ | `INFO` shows Linux mode bits via `lstat`; `file_info_reports_linux_permissions` |
| | Role-based permissions | ✔ | `PermissionService` + `User` hierarchy |
| | Transfer history in SQLite | ✔ | `transfers` table, `HISTORY` |
| 4 Use cases | Admin: manage users, view transfer logs, manage files, manage directories | ✔ | `USERS`, `HISTORY` (all), `AUDIT`, admin override of rename/delete/rmdir |
| | Admin: set permissions | ◐ | role changes (`SETROLE`) and share/unshare; per-file Unix mode editing is intentionally not offered (files are always 0640/0750) |
| | Faculty / Student use cases | ✔ | role matrix in README |
| 5 UML | `User` abstract + `Admin`/`Faculty`/`Student` with `canDelete()` | ✔ | `common/include/linsft/user.h`; `oop_user_hierarchy_polymorphism` |
| | `FileService`, `FileManager`, `AuthenticationService`, `PermissionService`, `TransferService`, `Database` | ◐ | same responsibilities under the names in the original brief (`AuthenticationManager`, `TransferManager`, `DatabaseManager`, …); mapping table in `docs/UML.md` |
| 6 ER diagram | `users` incl. `home_directory` | ✔ | column present, set to `/users/<name>`; password stored as `salt` + `pw_hash` (never plain) |
| | `files`, `transfers` | ◐ | `files.name/sha256` (poster: `filename/checksum`); `transfers.direction` (poster: `operation`); no FK on `transfers.user_id` so history survives user deletion; extra tables `directories`, `audit_logs` |
| 7 Folder structure | `include/ src/ server_storage/ database/ tests/ docs/ Makefile README.md` | ◐ | split into `common/ server/ client/` each with `include/ src/`; `server_storage/`, `database/`, `tests/`, `docs/` (`SRS.md`, `UML.md`, `Architecture.md`→`ARCHITECTURE.md`, `SDLC.md`, `TestCases.md`), `Makefile` (wrapper around CMake), `README.md`. Poster test files `test_fileops/search/security` correspond to the cases in `test_integration.cpp` (see `TestCases.md`) |
| 8 Server output | `./file_server 5000`, banner (Port/Storage/Database/Status), `[INFO]`, `[CLIENT]`, `[UPLOAD]`, `[DOWNLOAD]`, `[SEARCH]`, `[DELETE]` | ✔ | `file_server` alias + positional port; exact format shown in README §10; `activity_log_lines_and_search_audit` |
| 9 Client output | `./file_client 127.0.0.1 5000`, `Username:`/`Password: ********`, `Login successful! Role: STUDENT`, `LIST`, `DOWNLOAD`, `Checksum: VERIFIED`, `Download completed successfully.` | ✔ | `file_client` alias; masked prompt; case-insensitive commands; e2e test with `--prompt-login` |
| 10 File transfer flow | Upload: metadata → validate → chunks → write → checksum → success; Download: request → check → chunks → write → checksum → success | ✔ | `docs/UML.md` sequence diagrams |
| 11 Linux file operations | `open read write close stat mkdir rmdir opendir readdir closedir unlink rename` | ✔ | all used (`opendir/readdir/closedir` for staging cleanup and `/sys/block`; user listings come from SQLite metadata) |
| 12 10-day plan, 5 students | Task table and module split | ✔ | `docs/DEVELOPMENT_PLAN.md` maps each day/module to files and tests |
| Final result | Multi-client TCP; complete file management; secure authenticated access; working demo | ✔ | `docs/DEMO.md` |

## Differences kept on purpose
* **Build system:** CMake is the primary build (required by the original project brief); the `Makefile` wraps it, so `make`, `make test`, `make clean` work as on the poster.
* **Binary names:** `network-file-server` / `network-file-client` (original brief) plus the poster's `file_server` / `file_client` aliases.
* **Passwords:** the poster's `password` fields are stored as salted PBKDF2 hashes; the `User` object therefore has no password member.
* **Transport:** no TLS (see README limitations).
