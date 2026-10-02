# Development Plan (as executed)

| Phase | Deliverable | Verification |
|---|---|---|
| 1. Foundations | CMake project, SHA-256/HMAC/PBKDF2, protocol framing, path validation, RBAC table | `test_unit` (NIST/RFC vectors) |
| 2. Persistence | SQLite schema, `DatabaseManager`, `Logger`/`AuditLogger` | unit tests incl. injection strings |
| 3. Server core | Auth, FileManager, TransferManager, ConnectionHandler, ConnectionManager, SystemMonitor, `main` with signals and admin commands | CLI smoke tests |
| 4. Client | `Client` library (chunked transfer, checksum), CLI | `test_integration`, `test_e2e_cli` |
| 5. GUI | Qt6 `LoginDialog` + `MainWindow` with role-gated controls | `test_gui` (offscreen) + screenshot review |
| 6. Hardening | Hostile-input tests, concurrency, shutdown, crash recovery | integration suite repeated (flakiness hunt) |
| 7. Documentation & packaging | README, docs, scripts, git history, ZIP | clean-checkout build, `ctest`, README commands re-run |

## Defects found by the test-suite during development (and fixed)
1. Upload fields were parsed in a different order by server and client (found by CLI smoke test).
2. After a protocol violation the server closed with unread data pending, producing a TCP RST instead of FIN so the client could lose the error reply — now half-closes and drains first.
3. `INSERT` + `last_insert_rowid()` raced between threads, mis-assigning transfer-history rows under concurrency — replaced by atomic `DatabaseManager::insert()`.
4. The shipped `config/server.conf` (with inline `# comments`) was rejected by the config parser; found only when the README procedure was run from a fresh clone. Parser fixed and `shipped_config_file_parses` added so the real file is now under test.

## 10-Day Plan and Team Work Distribution (5 students)
Planned schedule and module ownership for the team presentation. Each module maps to real files and to tests that prove it.

| Day | Tasks | Deliverables (this repository) |
|---|---|---|
| 1 | Requirements, SRS, use cases | `docs/PRD.md`, `docs/SRS.md` |
| 2 | UML, architecture, database design | `docs/UML.md`, `docs/ARCHITECTURE.md`, `database/schema.sql` |
| 3 | OOP classes, authentication | `common/include/linsft/user.h`, `server/src/auth.cpp`, `common/src/permissions.cpp` |
| 4 | TCP server / client | `common/src/protocol.cpp`, `server/src/server.cpp`, `client/src/client.cpp` |
| 5 | Multithreading, connection handling | `ConnectionManager`, `ConnectionHandler`, graceful shutdown |
| 6 | File operations (upload / download) | `server/src/transfer_manager.cpp`, `server/src/file_manager.cpp` |
| 7 | Directory operations, search, metadata | directory/rename/search/info in `FileManager`, default layout and home directories |
| 8 | Permissions, checksum, security | `PermissionService`, `crypto.cpp` (SHA-256), `pathutil.cpp`, `docs/SECURITY.md` |
| 9 | Integration and testing | `tests/` (unit, integration, GUI, e2e), CLI + Qt GUI integration |
| 10 | Final demo, documentation, presentation | `README.md`, `docs/DEMO.md`, `LinSFT-Final.zip` |

| Student | Module | Main files | Proof (automated tests) |
|---|---|---|---|
| 1 | OOP + Authentication | `user.h/.cpp`, `auth.cpp`, `permissions.cpp` | `oop_user_hierarchy_polymorphism`, `rbac_matrix`, `registration_login_logout`, `brute_force_lockout` |
| 2 | Networking (TCP) | `protocol.cpp`, `server.cpp`, `connection_handler.cpp`, `client.cpp` | `protocol_*`, `malformed_and_hostile_network_input`, `concurrent_clients`, `graceful_shutdown_with_active_clients` |
| 3 | File Operations | `file_manager.cpp`, `transfer_manager.cpp` | `upload_download_roundtrip_sha256`, `directories_rename_search_info_delete`, `unicode_and_spaces_in_names` |
| 4 | Search + Security | search in `FileManager`, `pathutil.cpp`, `crypto.cpp`, path rules | `path_traversal_prevented`, `checksum_mismatch_detected_and_rejected`, `sha256_known_vectors`, `storage_layout_write_rules` |
| 5 | Database + Integration | `database.cpp`, `schema.sql`, `logger.cpp`, `system_monitor.cpp`, CLI/GUI, CMake, tests | `sqlite_prepared_statements_and_injection`, `persistence_across_restart`, `test_gui`, `test_e2e_cli` |
