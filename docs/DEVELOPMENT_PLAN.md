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
