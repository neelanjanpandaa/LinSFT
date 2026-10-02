# UML

## Class diagram (server side)
```mermaid
classDiagram
    class LinSFTServer { +start() +stop() }
    class Services { +init() }
    class ConnectionManager { +listen() +run() +stop() }
    class ConnectionHandler { +run() -dispatch() }
    class AuthenticationManager { +registerUser() +login() +validate() +logout() }
    class PermissionService { +has(role,perm)$ +canReadFile()$ +canDeleteFile()$ }
    class FileManager { +list() +search() +makeDir() +removeDir() +renameEntry() +removeFile() +commitUpload() }
    class TransferManager { +beginUpload() +uploadChunk() +finishUpload() +beginDownload() +downloadChunk() }
    class AuditLogger { +record() +recent() }
    class DatabaseManager { +query() +exec() +insert() }
    class SystemMonitor { +snapshot() }
    LinSFTServer --> Services
    LinSFTServer --> ConnectionManager
    ConnectionManager --> ConnectionHandler : thread per client
    ConnectionHandler --> Services
    Services o-- AuthenticationManager
    Services o-- FileManager
    Services o-- TransferManager
    Services o-- AuditLogger
    Services o-- DatabaseManager
    Services o-- SystemMonitor
    ConnectionHandler ..> PermissionService
    AuthenticationManager --> DatabaseManager
    FileManager --> DatabaseManager
    TransferManager --> DatabaseManager
    TransferManager --> FileManager
    AuditLogger --> DatabaseManager
```

## Class diagram (client side)
```mermaid
classDiagram
    class Client { +connectTo() +login() +upload() +download() +list() +search() +rename() ... }
    class MainWindow
    class LoginDialog
    class CliMain
    MainWindow --> Client
    LoginDialog --> Client
    CliMain --> Client
```

## Login sequence
```mermaid
sequenceDiagram
    participant C as Client
    participant H as ConnectionHandler
    participant A as AuthenticationManager
    participant D as SQLite
    C->>H: LOGIN(user, password)
    H->>A: login()
    A->>A: locked out? (5 failures / 60 s)
    A->>D: SELECT salt, hash, iterations WHERE username=?
    A->>A: PBKDF2 + constant-time compare
    A-->>H: Session(token, role)
    H->>D: audit LOGIN
    H-->>C: OK(token, userId, username, role)
```

## Download sequence
```mermaid
sequenceDiagram
    participant C as Client
    participant H as Handler
    participant T as TransferManager
    C->>H: DOWNLOAD_BEGIN(token, path)
    H->>H: validate path, RBAC canReadFile
    H->>T: beginDownload (open O_NOFOLLOW, fstat, history row)
    H-->>C: OK(tid, size, sha256)
    loop until eof
        C->>H: DOWNLOAD_CHUNK(tid)
        H-->>C: bytes (<=64 KiB), eof
    end
    C->>C: compare SHA-256 -> keep or delete .part
    C->>H: DOWNLOAD_END(tid, verified)
    H->>T: mark COMPLETED / FAILED
```

## Upload state machine
```mermaid
stateDiagram-v2
    [*] --> InProgress : UPLOAD_BEGIN (staging file + history row)
    InProgress --> InProgress : UPLOAD_CHUNK
    InProgress --> Completed : UPLOAD_END, size and SHA-256 match, rename(2)
    InProgress --> Failed : checksum / size mismatch, I/O error
    InProgress --> Aborted : client abort or disconnect, server shutdown
    Completed --> [*]
    Failed --> [*]
    Aborted --> [*]
```

## User class hierarchy (OOP model)
```mermaid
classDiagram
    class User {
        <<abstract>>
        -int64 id
        -string username
        -Role role
        +login()
        +logout()
        +canDelete(ownerId) bool*
        +create(Principal)$ User
    }
    class Student { +canDelete(ownerId) bool }
    class Faculty { +canDelete(ownerId) bool }
    class Admin { +canDelete(ownerId) bool }
    User <|-- Student
    User <|-- Faculty
    User <|-- Admin
    PermissionService ..> User : canDeleteFile() delegates
```
`Student`/`Faculty` may delete only their own files; `Admin` may delete any. The password is deliberately **not** a member: only salted hashes exist, in the database.

## Mapping to the class names on the project poster
| Poster class | In this code base | Notes |
|---|---|---|
| `User` (abstract), `Admin`, `Faculty`, `Student` | `User`, `Admin`, `Faculty`, `Student` (`common/include/linsft/user.h`) | `login()`, `logout()`, `canDelete()` present; no password field (hashes only in DB) |
| `FileService` (upload, download, delete, rename, list, search, getFileInfo) | request handlers in `ConnectionHandler` + `FileManager` + `TransferManager` | split by responsibility |
| `FileManager` (openFile, readFile, writeFile, createDir, removeDir, getFileInfo) | `FileManager` (`makeDir`, `removeDir`, `find`, `list`, …) and POSIX `open/read/write` in `TransferManager` | |
| `AuthenticationService` (authenticate, getUserRole) | `AuthenticationManager` (`login`, `validate` → `Session.role`) | name kept from the original project brief |
| `PermissionService` (checkPermission, getUserPath) | `PermissionService` (`has`, `canReadFile`, …, `canWriteInto`); home path in `users.home_directory` | |
| `TransferService` (sendFile, receiveFile, calculateHash) | `TransferManager` (`beginUpload/uploadChunk/finishUpload`, `beginDownload/downloadChunk`) + `Sha256` (`crypto.h`) | |
| `Database` (saveUser, saveTransfer, getHistory) | `DatabaseManager` (prepared-statement API) used by `AuthenticationManager`, `TransferManager`, `ConnectionHandler::hHistory` | |
| `NetworkServer` / `NetworkClient` | `ConnectionManager` + `ConnectionHandler` / `Client` | |
