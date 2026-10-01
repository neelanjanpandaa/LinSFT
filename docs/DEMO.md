# Demo script (about 8 minutes)

**Preparation (once):**
```bash
./network-file-server --seed-demo     # prints admin / faculty1 / student1 passwords and saves them to config/demo-credentials.txt
```

**Terminal 1:** `./network-file-server`  &nbsp; **Terminal 2:** `./network-file-gui`  (fallback: `./network-file-client`)

| Time | Action | What to say |
|---|---|---|
| 0:00 | Show `tree -L 2`, `README.md` | Layered architecture, C++17, SQLite, Qt6 |
| 0:45 | **Register** a new user `demo_user` in the GUI | Self-registration is always STUDENT; password stored as salted PBKDF2 |
| 1:30 | New Folder → Upload a file (private) → File Info | SHA-256 verified by the server; stored as a real file with mode 0640 (`ls -l storage/`) |
| 3:00 | Download it; in a shell `sha256sum` both copies | End-to-end integrity |
| 3:45 | Share, Search, Rename, Delete, Remove Folder | Ownership checks; non-empty directory refused |
| 4:45 | Transfer History tab | History per user |
| 5:15 | Logout → login as **admin** (password from `config/demo-credentials.txt`) | RBAC: extra tabs appear |
| 5:30 | Users → change `demo_user` to FACULTY; Audit Log | Role changes apply to live sessions; everything audited |
| 6:15 | System Monitor | Reads `/proc`, `/sys`, `/proc/devices`; shows the `/dev/urandom` char device and its driver |
| 6:45 | Terminal: `./network-file-client` as `student1`: `info ../../etc/passwd`, `mkdir ../x` | Path traversal rejected; audit shows the attempts |
| 7:15 | `cd build && ctest` (or show last results) | 4 suites, 700+ automated checks |
| 7:45 | Ctrl+C in the server terminal | Graceful shutdown: sockets closed, threads joined, exit 0 |

**Tip:** `./scripts/run_demo.sh` seeds accounts if needed, starts the server and opens the GUI in one step.
