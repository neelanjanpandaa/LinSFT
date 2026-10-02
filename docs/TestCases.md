# Test Cases

Each case lists the manual steps (GUI or CLI) and the automated test that covers it. Run the automated ones with
`cd build && ctest --output-on-failure` (add `-R <name>` to run one suite).

| ID | Area | Steps | Expected result | Automated test |
|---|---|---|---|---|
| TC-01 | Registration | `REGISTER alice` with an 8+ char password | "registered"; account is STUDENT; `/users/alice` exists | `registration_login_logout`, `default_layout_home_dirs_and_write_rules` |
| TC-02 | Registration validation | Register a duplicate / short name / short password / `a'; DROP TABLE…` | Rejected with a clear error; database untouched | `registration_login_logout`, `name_user_password_validation` |
| TC-03 | Login | Login with correct password | `Login successful! Role: STUDENT` | `registration_login_logout`, e2e |
| TC-04 | Login failure | Wrong password / unknown user | `AUTH_FAILED` (same message for both) | `registration_login_logout` |
| TC-05 | Lockout | 5 wrong passwords, then the right one | `LOCKED_OUT` for 60 s | `brute_force_lockout` |
| TC-06 | Logout / token replay | Logout, then reuse the old token | `AUTH_REQUIRED` | `registration_login_logout` |
| TC-07 | Unauthenticated access | Send any command without login | `AUTH_REQUIRED` | `unauthenticated_requests_rejected` |
| TC-08 | Upload | `UPLOAD file /documents` | `Checksum: VERIFIED`, file on disk with mode 0640 | `upload_download_roundtrip_sha256`, e2e |
| TC-09 | Large / odd sizes | Upload empty, 700 KB, exact 128 KiB files | All round-trip identically | `upload_download_roundtrip_sha256` |
| TC-10 | Download | `DOWNLOAD /documents/file` then `sha256sum` both | Identical hashes; `Checksum: VERIFIED` | `upload_download_roundtrip_sha256`, e2e |
| TC-11 | Integrity failure (upload) | Announce a wrong SHA-256 | `CHECKSUM_MISMATCH`, nothing published, staging file removed | `checksum_mismatch_detected_and_rejected` |
| TC-12 | Integrity failure (storage) | Modify a stored file on disk, download it | Client reports mismatch, deletes the partial file | `checksum_mismatch_detected_and_rejected` |
| TC-13 | Protocol misuse | Oversized/incomplete/unknown transfer ids | Proper error codes, no leaks | `upload_protocol_misuse` |
| TC-14 | File size limit | Upload over `max_file_size` | `TOO_LARGE` | `max_file_size_enforced` |
| TC-15 | List | `LIST` / `LIST -l` | Numbered listing with `<DIR>` / size; only visible files | `ownership_and_visibility_rules`, e2e |
| TC-16 | Search | `SEARCH report` (case-insensitive, recursive); `SEARCH %` | Matches by name across all directories; `%` is literal | `directories_rename_search_info_delete` |
| TC-17 | File info | `INFO /documents/file` | Size, SHA-256, owner, **permissions `-rw-r-----`**, times | `file_info_reports_linux_permissions`, e2e |
| TC-18 | Rename | Rename own file / directory with children | Paths of descendants follow; disk matches | `directories_rename_search_info_delete`, `unicode_and_spaces_in_names` |
| TC-19 | Delete | Delete own file; another user's file | OK; `FORBIDDEN` for others (admin may) | `ownership_and_visibility_rules` |
| TC-20 | Directories | `MKDIR`, `RMDIR` (empty / non-empty / not owner) | Created with mode 0750; non-empty → `NOT_EMPTY`; not owner → `FORBIDDEN` | `directories_rename_search_info_delete` |
| TC-21 | Share | Share a private file, other user downloads, unshare | Allowed then `FORBIDDEN` | `ownership_and_visibility_rules` |
| TC-22 | Default layout | Start a fresh server, `LIST /` | `public documents temporary users` exist (owner `system`) | `default_layout_home_dirs_and_write_rules`, e2e |
| TC-23 | Home directories | Other user tries `MKDIR/UPLOAD` in `/users/alice` | `FORBIDDEN`, audit entry `DENIED` | `default_layout_home_dirs_and_write_rules`, `storage_layout_write_rules` |
| TC-24 | Public auto-share | Upload to `/public` without sharing, other user downloads | Allowed | `public_directory_auto_shares_files` |
| TC-25 | Path traversal | `INFO ../../etc/passwd`, `MKDIR ../x`, upload name `../x`, rename to `../x` | `INVALID_PATH`; nothing created outside storage; audited | `path_traversal_prevented`, `path_validation_blocks_traversal`, e2e |
| TC-26 | Symlink planting | Plant a symlink in storage, request it | `NOT_FOUND` (never followed) | `path_traversal_prevented` |
| TC-27 | Transfer history | Student vs faculty `HISTORY` | Own vs all users | `transfer_history_scoping` |
| TC-28 | Audit trail | Admin `AUDIT` after various actions | LOGIN/UPLOAD/DOWNLOAD/SEARCH/DENIED… present with client address | `audit_logging_covers_auth_and_files`, `activity_log_lines_and_search_audit` |
| TC-29 | RBAC (student) | `USERS`, `AUDIT`, `SYSINFO` | `FORBIDDEN` | `rbac_admin_functions_restricted`, e2e |
| TC-30 | RBAC (faculty) | `SYSINFO`, read others' private files, try delete them | OK / OK / `FORBIDDEN` | `rbac_admin_functions_restricted`, `ownership_and_visibility_rules` |
| TC-31 | User management | Admin `SETROLE`, `DELUSER`, demote last admin | Applied to live sessions; files reassigned; last admin protected | `admin_user_management`, `admin_dashboard_user_management`, e2e |
| TC-32 | OOP model | Student/Faculty/Admin `canDelete()` | Polymorphic results match `PermissionService` | `oop_user_hierarchy_polymorphism`, `rbac_matrix` |
| TC-33 | Hostile network input | HTTP text, oversized header, truncated frame, unknown type | Error reply + clean close; server stays healthy | `malformed_and_hostile_network_input`, `protocol_*` |
| TC-34 | Disconnect mid-upload | Kill client during upload | Staging file removed, transfer `ABORTED` | `client_disconnect_mid_transfer_cleans_up` |
| TC-35 | Concurrency | 12 clients upload/download/delete simultaneously (plus 6 parallel CLIs) | All succeed, history rows consistent | `concurrent_clients`, e2e |
| TC-36 | Client limit | More than `max_clients` connections | Extra client refused | `max_clients_limit` |
| TC-37 | Graceful shutdown | `Ctrl+C` / `SIGINT` with active clients | Exit code 0, port closed, threads joined, no staging files | `graceful_shutdown_with_active_clients`, e2e |
| TC-38 | Persistence / recovery | Restart server; stale `IN_PROGRESS` rows | Data and passwords survive; stale rows → `FAILED` | `persistence_across_restart`, `stale_transfers_recovered_on_startup` |
| TC-39 | Server console format | Start `./file_server 5000`, do some actions | Banner, `[CLIENT]`, `[UPLOAD]`, `[DOWNLOAD]`, `[SEARCH]`, `[DELETE]`, `[DENIED]` lines | `activity_log_lines_and_search_audit`, e2e |
| TC-40 | CLI session | Prompted login, masked password, upper-case commands | `Login successful! Role: …`, `Server files:` listing | e2e (`--prompt-login`) |
| TC-41 | Config file | Start with the shipped `config/server.conf` (inline comments) | Parses; invalid values reported | `shipped_config_file_parses` |
| TC-42 | GUI dashboard | Every button on Files / History / Users / Audit / System tabs | Real action; role-gated tabs and buttons | `student_dashboard_all_actions`, `faculty_dashboard`, `admin_dashboard_user_management`, `student_cannot_modify_others_in_ui` |
| TC-43 | GUI session loss | Stop the server while the GUI is open | GUI logs out cleanly | `session_loss_logs_out_gui` |
| TC-44 | Cryptography | NIST/RFC test vectors | SHA-256, HMAC-SHA256, PBKDF2 correct | `sha256_known_vectors`, `hmac_and_pbkdf2_vectors` |
| TC-45 | SQL injection | Store `x'); DROP TABLE users; --` as data | Stored literally; tables intact | `sqlite_prepared_statements_and_injection` |
