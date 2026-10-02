# Software Development Life Cycle — LinSFT

## Model
**Iterative–incremental** with a test-first bias for the risky parts (protocol, security, concurrency). Each increment ends with a runnable system and a green test-suite.

| Phase | Activities | Artefacts |
|---|---|---|
| 1. Requirements | Stakeholder brief, roles, use cases, constraints (Linux, C++17) | `PRD.md`, `SRS.md` |
| 2. Design | Layered architecture, protocol, schema, class model, security design | `ARCHITECTURE.md`, `UML.md`, `database/schema.sql` |
| 3. Implementation | Increments: crypto/protocol → DB/auth → file & transfer managers → server → client/CLI → GUI → layout/OOP/logging refinements | `common/ server/ client/` |
| 4. Verification | Unit, integration, GUI and end-to-end suites; hostile-input and concurrency tests; fresh-clone build | `tests/`, `TESTING.md`, `TestCases.md` |
| 5. Release | CMake + Makefile build, scripts, README, ZIP with git history | `LinSFT-Final.zip` |
| 6. Maintenance | Defect log, regression test added for every defect | `DEVELOPMENT_PLAN.md` |

## Quality gates (definition of done)
1. Builds from a clean clone with zero compiler warnings (`-Wall -Wextra -Wpedantic -Wshadow`).
2. `ctest` passes: unit, integration, GUI (offscreen) and end-to-end suites.
3. The README procedure is executed literally on a fresh clone.
4. No TODO/FIXME, no placeholder UI controls, no non-C++ application code.
5. Every defect found gets a regression test.

## Risk management
| Risk | Mitigation |
|---|---|
| Concurrency bugs | Thread-per-client with explicit locks, 12-client stress test, repeated runs to expose flakiness |
| Data loss / corruption | Staging file + SHA-256 + `fsync` + atomic `rename(2)`, tampering test |
| Path traversal / injection | Central validation, `O_NOFOLLOW`, prepared statements, dedicated hostile-input tests |
| Environment differences (WSL2) | Only standard Ubuntu packages; GUI optional with CLI fallback |
| Scope creep | Out-of-scope list in `PRD.md` (TLS, resumable transfers, quotas) |

## Tooling
g++ 13, CMake, GNU Make wrapper, Git (one commit per increment), Qt Widgets, SQLite CLI for inspection, `sha256sum` for independent integrity checks.
