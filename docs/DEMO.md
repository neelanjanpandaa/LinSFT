# Demo script (about 8 minutes)

**Preparation (once):**
```bash
./file_server --seed-demo     # prints admin / faculty1 / student1 passwords and saves them to config/demo-credentials.txt
```

**Terminal 1:** `./file_server 5000` &nbsp; **Terminal 2:** `./network-file-gui`  (fallback: `./file_client 127.0.0.1 5000`)

| Time | Action | What to say |
|---|---|---|
| 0:00 | Show `tree -L 2`, `README.md`, the server banner | Layered architecture, C++17, SQLite, Qt6; default layout `public/ documents/ users/ temporary/` |
| 0:45 | **Register** a new user `demo_user` in the GUI | Self-registration is always STUDENT; salted PBKDF2; a private home `/users/demo_user` is created |
| 1:30 | New Folder → Upload a file (private) → File Info | SHA-256 verified by the server; File Info shows Linux permissions `-rw-r-----`; server console prints `[UPLOAD] …` |
| 3:00 | Download it; in a shell `sha256sum` both copies | End-to-end integrity; `[DOWNLOAD] …` in the server console |
| 3:45 | Share, Search, Rename, Delete, Remove Folder | Ownership checks; non-empty directory refused; `[SEARCH] … (N files found)` |
| 4:30 | Upload into **public/** without sharing; log in as another user | Files in `/public` are auto-shared; other users' homes are not writable |
| 4:45 | Transfer History tab | History per user |
| 5:15 | Logout → login as **admin** (password from `config/demo-credentials.txt`) | RBAC: extra tabs appear |
| 5:30 | Users → change `demo_user` to FACULTY; Audit Log | Role changes apply to live sessions; everything audited |
| 6:15 | System Monitor | Reads `/proc`, `/sys`, `/proc/devices`; shows the `/dev/urandom` char device and its driver |
| 6:45 | CLI as `student1`: `INFO ../../etc/passwd`, `MKDIR /users/other` | Path traversal rejected, foreign home refused; `[DENIED]` lines on the server |
| 7:15 | `make test` (or show last results) | 4 suites, 900+ automated checks |
| 7:45 | Ctrl+C in the server terminal | Graceful shutdown: sockets closed, threads joined, exit 0 |

**Tip:** `./scripts/run_demo.sh` (or `make demo`) seeds accounts if needed, starts the server and opens the GUI in one step.
