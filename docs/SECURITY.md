# Security

## Threat model
Authenticated and unauthenticated clients on the network may send arbitrary bytes. The server must not leak or modify data outside the
rules of the RBAC model, must not be crashable by malformed input, and must keep credentials safe at rest.
**Out of scope:** passive/active network attackers (no TLS), a malicious local root user, denial-of-service by volume.

## Controls and where they are tested
| Control | Implementation | Test |
|---|---|---|
| Salted password hashing | 16-byte random salt, PBKDF2-HMAC-SHA256, 100 000 iterations (configurable, stored per user), `/dev/urandom` | `registration_login_logout`, RFC 7914 vector in `hmac_and_pbkdf2_vectors` |
| Timing / enumeration | constant-time compare; dummy PBKDF2 for unknown users | code review |
| Brute-force lockout | 5 failures ⇒ 60 s per username | `brute_force_lockout` |
| Session validation | 256-bit tokens checked on every request, sliding 30 min expiry, revoked on logout/delete | `registration_login_logout`, `unauthenticated_requests_rejected`, `admin_user_management` |
| RBAC | `PermissionService` is the single source of truth | `rbac_matrix`, `ownership_and_visibility_rules`, `rbac_admin_functions_restricted` |
| Ownership checks | owner or role-based `*_ANY` permission for rename/delete/share/rmdir/overwrite | `ownership_and_visibility_rules` |
| Path traversal | canonical virtual paths; `..`, backslash, control chars, hidden names rejected; `O_NOFOLLOW`; planted symlinks ignored | `path_validation_blocks_traversal`, `path_traversal_prevented` |
| Input validation | usernames, passwords, names, SHA-256 hex, roles, lengths | `name_user_password_validation`, `malformed_and_hostile_network_input` |
| SQL injection | prepared statements with bound parameters only; `instr()` instead of `LIKE` | `sqlite_prepared_statements_and_injection`, `directories_rename_search_info_delete` |
| Integrity | SHA-256 verified server-side (upload) and client-side (download) | `checksum_mismatch_detected_and_rejected` |
| Atomic publish | staging file → verify → `fsync` → `rename(2)` + DB transaction | `upload_download_roundtrip_sha256`, `client_disconnect_mid_transfer_cleans_up` |
| Safe file modes | files 0640, dirs 0750, DB 0600, credentials 0600 | `upload_download_roundtrip_sha256`, `directories_*`, `test_e2e_cli` |
| Protocol robustness | magic/version/length checks, bounds-checked reader, 1 MiB cap, clean close | `protocol_*`, `malformed_and_hostile_network_input` |
| Resource limits | `max_clients`, `max_file_size`, idle timeout, 8 transfers/connection | `max_clients_limit`, `max_file_size_enforced` |
| Audit trail | all auth events, file operations, denied/rejected attempts; log-line sanitising | `audit_logging_covers_auth_and_files`, `ownership_and_visibility_rules` |
| Cleanup / threads | RAII, joined threads, closed fds, removed staging files | `graceful_shutdown_with_active_clients`, `test_e2e_cli` |

## Known weaknesses (honest list)
1. **No transport encryption.** Passwords and file data cross the network in clear text. Mitigation: bind to localhost (default) or use an SSH tunnel.
2. Session tokens are bearer tokens; anyone who can read the traffic can replay them.
3. Lockout is per username, so an attacker can lock a victim out (accepted trade-off; admin can reset with `--init-admin`).
4. Thread-per-client can be exhausted by many idle connections (mitigated by `max_clients` and the idle timeout).
5. Files are stored unencrypted on disk (protected only by Linux permissions).
6. The server process runs with the privileges of whoever starts it; run it as an unprivileged user.
