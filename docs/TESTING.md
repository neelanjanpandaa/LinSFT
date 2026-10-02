# Testing

## Automated (run `cd build && ctest --output-on-failure`)
| Suite | Cases / checks | Notes |
|---|---|---|
| `test_unit` | 16 / 247 | no network needed |
| `test_integration` | 27 / 624 | starts a real `LinSFTServer` on an ephemeral port per test, temp dir, real SQLite |
| `test_gui` | 6 / 110 | `QT_QPA_PLATFORM=offscreen` (set by CTest) |
| `test_e2e_cli` | 57 checks | real server + CLI processes, `SIGINT` shutdown |

All tests execute real code paths; none stub the network, the database or the filesystem.

## Requirement → test traceability
| Requirement | Test(s) |
|---|---|
| Protocol serialisation | `protocol_writer_reader_roundtrip`, `protocol_header_validation`, `protocol_message_over_socketpair`, `protocol_response_and_models` |
| TCP communication | `tcp_ping_and_banner`, all integration tests |
| Registration / login / logout | `registration_login_logout`, `login_dialog_flows`, e2e |
| RBAC | `rbac_matrix`, `rbac_admin_functions_restricted`, `ownership_and_visibility_rules`, `faculty_dashboard` |
| Upload / download / SHA-256 | `upload_download_roundtrip_sha256`, `checksum_mismatch_detected_and_rejected`, `upload_protocol_misuse` |
| Path traversal | `path_validation_blocks_traversal`, `path_traversal_prevented` |
| Rename / delete / mkdir / rmdir / search / info | `directories_rename_search_info_delete`, `unicode_and_spaces_in_names`, `student_dashboard_all_actions` |
| History | `transfer_history_scoping` |
| User management | `admin_user_management`, `admin_dashboard_user_management` |
| Concurrent clients | `concurrent_clients`, e2e (6 parallel CLIs) |
| SQLite | `sqlite_prepared_statements_and_injection`, `persistence_across_restart`, `stale_transfers_recovered_on_startup` |
| Graceful shutdown | `graceful_shutdown_with_active_clients`, e2e SIGINT |

## Manual test checklist (GUI)
| # | Step | Expected |
|---|---|---|
| 1 | Start server, start GUI, wrong password | Red error under the form |
| 2 | Register `alice` (min 8-char password) | Signed in as STUDENT; only *Files* and *Transfer History* tabs |
| 3 | New Folder `docs`; double-click it | Path bar shows `/docs` |
| 4 | Upload a file, answer "No" (private) | Row appears; Download/Rename/Delete enabled on selection |
| 5 | File Info | Shows size and SHA-256 equal to `sha256sum` of the original |
| 6 | Download to `~/out`, run `sha256sum` | Identical hash |
| 7 | Share / Unshare | "Shared" column toggles Yes/No |
| 8 | Search part of the name | Result list with full paths |
| 9 | Rename, Delete, Up, Remove Folder | Each succeeds; non-empty folder refused with message |
| 10 | Transfer History | Upload + download rows, status COMPLETED |
| 11 | Logout, log in as `admin` | Extra tabs: System Monitor, Users, Audit Log |
| 12 | Users → select user → Change Role | Role changes; audit log shows `USER_SET_ROLE` |
| 13 | Ctrl+C in server terminal | "shutting down gracefully", process exits 0; GUI reports session ended on next action |

See [`TestCases.md`](TestCases.md) for the full list of 45 numbered test cases (steps, expected result, covering automated test).
