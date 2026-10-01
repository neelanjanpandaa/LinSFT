-- LinSFT SQLite schema. Embedded into the server at build time (see CMakeLists.txt).
-- All application queries use prepared statements with bound parameters.

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    salt        TEXT    NOT NULL,                 -- 16 random bytes, hex
    pw_hash     TEXT    NOT NULL,                 -- PBKDF2-HMAC-SHA256, hex
    iterations  INTEGER NOT NULL,
    role        TEXT    NOT NULL CHECK (role IN ('ADMIN','FACULTY','STUDENT')),
    created_at  INTEGER NOT NULL,
    last_login  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS directories (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    path        TEXT    NOT NULL UNIQUE,          -- normalised virtual path, e.g. /docs
    name        TEXT    NOT NULL,
    parent      TEXT    NOT NULL,
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dirs_parent ON directories(parent);

CREATE TABLE IF NOT EXISTS files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    path        TEXT    NOT NULL UNIQUE,          -- normalised virtual path
    name        TEXT    NOT NULL,
    parent      TEXT    NOT NULL,
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    size        INTEGER NOT NULL,
    sha256      TEXT    NOT NULL,
    shared      INTEGER NOT NULL DEFAULT 0 CHECK (shared IN (0,1)),
    created_at  INTEGER NOT NULL,
    modified_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_parent ON files(parent);
CREATE INDEX IF NOT EXISTS idx_files_owner  ON files(owner_id);

CREATE TABLE IF NOT EXISTS transfers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,                 -- no FK: history outlives deleted users
    username    TEXT    NOT NULL,
    direction   TEXT    NOT NULL CHECK (direction IN ('UPLOAD','DOWNLOAD')),
    file_path   TEXT    NOT NULL,
    size        INTEGER NOT NULL DEFAULT 0,
    sha256      TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL CHECK (status IN ('IN_PROGRESS','COMPLETED','FAILED','ABORTED')),
    detail      TEXT    NOT NULL DEFAULT '',
    client_addr TEXT    NOT NULL DEFAULT '',
    started_at  INTEGER NOT NULL,
    finished_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_transfers_user ON transfers(user_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    user_id     INTEGER NOT NULL DEFAULT 0,
    username    TEXT    NOT NULL DEFAULT '',
    action      TEXT    NOT NULL,
    target      TEXT    NOT NULL DEFAULT '',
    result      TEXT    NOT NULL,                 -- SUCCESS | DENIED | FAILURE
    client_addr TEXT    NOT NULL DEFAULT '',
    detail      TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);
