// Integration tests: a real LinSFTServer on an ephemeral TCP port, real Client objects over
// real sockets, real files on disk and a real SQLite database in a temp directory.
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <random>
#include <sstream>
#include <thread>

#include "linsft/client.h"
#include "linsft/crypto.h"
#include "linsft/server.h"
#include "test_framework.h"

using namespace linsft;
namespace fs_ = std::chrono;

static std::string readFile(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss; ss << f.rdbuf(); return ss.str();
}
static void writeFile(const std::string& p, const std::string& d) { std::ofstream f(p, std::ios::binary); f << d; }
static std::string randomData(size_t n) {
    std::string s(n, 0);
    std::mt19937 g(unsigned(n) * 2654435761u);
    for (auto& c : s) c = char(g());
    return s;
}
static size_t countFiles(const std::string& dir) {
    size_t n = 0;
    if (DIR* d = opendir(dir.c_str())) { while (auto* e = readdir(d)) if (e->d_name[0] != '.' || (e->d_name[1] && e->d_name[1] != '.')) ++n; closedir(d); }
    return n;
}

struct Env {
    std::string dir;
    ServerConfig cfg;
    std::unique_ptr<LinSFTServer> srv;
    explicit Env(uint64_t maxFile = 64ULL * 1024 * 1024, const std::string& existingDir = "") {
        if (existingDir.empty()) {
            char tmpl[] = "/tmp/linsft-it-XXXXXX";
            dir = mkdtemp(tmpl);
        } else dir = existingDir;
        cfg.port = 0;
        cfg.storageDir = dir + "/storage";
        cfg.dbPath = dir + "/db.sqlite";
        cfg.logPath = dir + "/server.log";
        cfg.pbkdf2Iterations = 1000;  // fast for tests; production default is 100000
        cfg.logToConsole = false;
        cfg.maxFileSize = maxFile;
        start();
    }
    void start() {
        srv = std::make_unique<LinSFTServer>(cfg);
        std::string err;
        if (!srv->start(err)) { std::printf("SERVER START FAILED: %s\n", err.c_str()); std::abort(); }
    }
    ~Env() { if (srv) srv->stop(); srv.reset(); std::string cmd = "rm -rf " + dir; if (system(cmd.c_str())) {} }
    uint16_t port() const { return srv->port(); }
    std::string tmp(const std::string& n) const { return dir + "/" + n; }
    std::string store() const { return cfg.storageDir; }
    void makeUser(const std::string& u, Role r) {
        std::string m;
        CHECK(srv->services().auth.createOrUpdateUser(u, "Password-" + u, r, m) == Status::OK);
    }
    std::unique_ptr<Client> client(const std::string& user = "", bool create = true, Role role = Role::STUDENT) {
        auto c = std::make_unique<Client>();
        Result r = c->connectTo("127.0.0.1", port());
        if (!r.ok) { std::printf("connect failed: %s\n", r.message.c_str()); std::abort(); }
        if (!user.empty()) {
            if (create) makeUser(user, role);
            Result lr = c->login(user, "Password-" + user);
            if (!lr.ok) { std::printf("login(%s) failed: %s\n", user.c_str(), lr.message.c_str()); std::abort(); }
        }
        return c;
    }
};

static bool upload(Client& c, Env& e, const std::string& name, const std::string& data, const std::string& dir = "/",
                   bool shared = false, bool overwrite = false, Result* out = nullptr) {
    std::string local = e.tmp("up-" + name);
    writeFile(local, data);
    Result r = c.upload(local, dir, name, shared, overwrite);
    if (out) *out = r;
    return r.ok;
}

// ---------------------------------------------------------------------------
TEST(tcp_ping_and_banner) {
    Env e;
    Client c;
    CHECK(c.connectTo("127.0.0.1", e.port()).ok);
    CHECK(c.ping().ok);
    Client bad;
    CHECK(!bad.connectTo("127.0.0.1", 1, 2).ok);  // nothing listens on port 1: clean failure
}

TEST(registration_login_logout) {
    Env e;
    auto c = e.client();
    CHECK(c->registerUser("alice", "correct-horse").ok);
    CHECK_EQ(c->registerUser("alice", "another-pass1").status, Status::EXISTS);
    CHECK_EQ(c->registerUser("ALICE", "another-pass1").status, Status::EXISTS);         // case-insensitive
    CHECK_EQ(c->registerUser("bo", "correct-horse").status, Status::BAD_REQUEST);       // short name
    CHECK_EQ(c->registerUser("carol", "short").status, Status::BAD_REQUEST);            // short password
    CHECK_EQ(c->registerUser("a'; DROP TABLE users;--", "correct-horse").status, Status::BAD_REQUEST);
    CHECK_EQ(c->login("alice", "wrong-password").status, Status::AUTH_FAILED);
    CHECK_EQ(c->login("nobody", "correct-horse").status, Status::AUTH_FAILED);
    CHECK(!c->loggedIn());
    CHECK(c->login("alice", "correct-horse").ok);
    CHECK(c->role() == Role::STUDENT);                                                  // self-registration is always STUDENT
    std::string tok = c->token();
    std::vector<FileEntry> v;
    CHECK(c->list("/", v).ok);
    CHECK(c->logout().ok);
    c->setToken(tok);                                                                   // replay the old token
    CHECK_EQ(c->list("/", v).status, Status::AUTH_REQUIRED);
    c->setToken(std::string(64, 'a'));                                                  // forged token
    CHECK_EQ(c->list("/", v).status, Status::AUTH_REQUIRED);
    c->setToken("short");
    CHECK_EQ(c->list("/", v).status, Status::AUTH_REQUIRED);
    // password is never stored in clear text
    std::string dbBytes = readFile(e.dir + "/db.sqlite");
    CHECK(dbBytes.find("correct-horse") == std::string::npos);
    auto rows = e.srv->services().db.query("SELECT salt,pw_hash,iterations FROM users WHERE username='alice'");
    CHECK_EQ(DatabaseManager::asStr(rows[0][0]).size(), size_t(32));
    CHECK_EQ(DatabaseManager::asStr(rows[0][1]).size(), size_t(64));
}

TEST(unauthenticated_requests_rejected) {
    Env e;
    Client c;
    CHECK(c.connectTo("127.0.0.1", e.port()).ok);
    c.setToken(std::string(64, '0'));
    std::vector<FileEntry> v; FileEntry fe; std::vector<TransferEntry> h; std::vector<UserEntry> u;
    CHECK_EQ(c.list("/", v).status, Status::AUTH_REQUIRED);
    CHECK_EQ(c.search("x", v).status, Status::AUTH_REQUIRED);
    CHECK_EQ(c.info("/", fe).status, Status::AUTH_REQUIRED);
    CHECK_EQ(c.makeDir("/x").status, Status::AUTH_REQUIRED);
    CHECK_EQ(c.removeFile("/x").status, Status::AUTH_REQUIRED);
    CHECK_EQ(c.history(5, h).status, Status::AUTH_REQUIRED);
    CHECK_EQ(c.listUsers(u).status, Status::AUTH_REQUIRED);
    CHECK_EQ(c.upload("/etc/hostname", "/", "h", false, false).status, Status::AUTH_REQUIRED);
    CHECK_EQ(c.download("/x", e.tmp("o")).status, Status::AUTH_REQUIRED);
}

TEST(brute_force_lockout) {
    Env e;
    e.makeUser("victim", Role::STUDENT);
    auto c = e.client();
    for (int i = 0; i < 5; ++i) CHECK_EQ(c->login("victim", "bad-guess-" + std::to_string(i)).status, Status::AUTH_FAILED);
    CHECK_EQ(c->login("victim", "Password-victim").status, Status::LOCKED_OUT);         // even the right password is refused
}

TEST(upload_download_roundtrip_sha256) {
    Env e;
    auto c = e.client("alice");
    std::string data = randomData(700 * 1000 + 13);  // multiple chunks, not chunk-aligned
    CHECK(upload(*c, e, "data.bin", data));
    FileEntry fi;
    CHECK(c->info("/data.bin", fi).ok);
    CHECK_EQ(fi.size, uint64_t(data.size()));
    CHECK_EQ(fi.sha256, Sha256::hashHex(data));
    CHECK_EQ(fi.owner, std::string("alice"));
    // bytes really are on the Linux filesystem, with restrictive permissions
    struct stat st{};
    CHECK(stat((e.store() + "/data.bin").c_str(), &st) == 0);
    CHECK_EQ(uint64_t(st.st_size), uint64_t(data.size()));
    CHECK_EQ(int(st.st_mode & 0777), 0640);
    CHECK_EQ(readFile(e.store() + "/data.bin"), data);
    std::string out = e.tmp("down.bin"), sha;
    Result r = c->download("/data.bin", out, false, nullptr, &sha);
    CHECK(r.ok);
    CHECK_EQ(readFile(out), data);
    CHECK_EQ(sha, fi.sha256);
    CHECK_EQ(c->download("/data.bin", out).status, Status::EXISTS);                     // won't clobber local file
    CHECK(c->download("/data.bin", out, true).ok);
    // empty file
    CHECK(upload(*c, e, "empty.txt", ""));
    CHECK(c->download("/empty.txt", e.tmp("empty.out")).ok);
    CHECK_EQ(readFile(e.tmp("empty.out")).size(), size_t(0));
    // exact multiple of chunk size
    std::string exact = randomData(CHUNK_SIZE * 2);
    CHECK(upload(*c, e, "exact.bin", exact));
    CHECK(c->download("/exact.bin", e.tmp("exact.out")).ok);
    CHECK_EQ(readFile(e.tmp("exact.out")), exact);
    // duplicate upload refused unless overwrite
    Result dr;
    CHECK(!upload(*c, e, "data.bin", "other", "/", false, false, &dr));
    CHECK_EQ(dr.status, Status::EXISTS);
    CHECK(upload(*c, e, "data.bin", "replaced", "/", false, true));
    CHECK_EQ(readFile(e.store() + "/data.bin"), std::string("replaced"));
    CHECK_EQ(countFiles(e.store() + "/.tmp"), size_t(0));                               // staging dir is clean
    // missing local file / missing remote file
    CHECK_EQ(c->upload("/nonexistent/file", "/", "x").status, Status::IO_ERROR);
    CHECK_EQ(c->download("/nope.bin", e.tmp("nope")).status, Status::NOT_FOUND);
    CHECK(access(e.tmp("nope.part").c_str(), F_OK) != 0);                               // no stray .part
}

TEST(checksum_mismatch_detected_and_rejected) {
    Env e;
    auto c = e.client("alice");
    std::string data = "the real bytes";
    Writer w; w.str(c->token()).str("/").str("bad.txt").u64(data.size()).str(Sha256::hashHex("different")).boolean(false).boolean(false);
    std::vector<uint8_t> p; size_t off = 0;
    CHECK(c->rawCall(MsgType::UPLOAD_BEGIN, w, p, off).ok);
    Reader rd(p.data() + off, p.size() - off);
    uint32_t tid = rd.u32();
    Writer ch; ch.str(c->token()).u32(tid).bytes(data.data(), data.size());
    CHECK(c->rawCall(MsgType::UPLOAD_CHUNK, ch, p, off).ok);
    Writer en; en.str(c->token()).u32(tid);
    CHECK_EQ(c->rawCall(MsgType::UPLOAD_END, en, p, off).status, Status::CHECKSUM_MISMATCH);
    FileEntry fi;
    CHECK_EQ(c->info("/bad.txt", fi).status, Status::NOT_FOUND);                        // never published
    CHECK(access((e.store() + "/bad.txt").c_str(), F_OK) != 0);
    CHECK_EQ(countFiles(e.store() + "/.tmp"), size_t(0));
    std::vector<TransferEntry> h;
    CHECK(c->history(10, h).ok);
    CHECK(!h.empty() && h[0].status == "FAILED");

    // tampering with a stored file on disk is caught by the client on download
    CHECK(upload(*c, e, "t.txt", "original-content"));
    writeFile(e.store() + "/t.txt", "tampered-content");
    Result r = c->download("/t.txt", e.tmp("t.out"));
    CHECK_EQ(r.status, Status::CHECKSUM_MISMATCH);
    CHECK(access(e.tmp("t.out").c_str(), F_OK) != 0);                                   // corrupt data not left behind
    CHECK(c->history(10, h).ok);
    CHECK(h[0].direction == "DOWNLOAD" && h[0].status == "FAILED");
}

TEST(upload_protocol_misuse) {
    Env e;
    auto c = e.client("alice");
    // more data than announced
    Writer w; w.str(c->token()).str("/").str("m.txt").u64(4).str(Sha256::hashHex("abcd")).boolean(false).boolean(false);
    std::vector<uint8_t> p; size_t off = 0;
    CHECK(c->rawCall(MsgType::UPLOAD_BEGIN, w, p, off).ok);
    uint32_t tid = Reader(p.data() + off, p.size() - off).u32();
    Writer ch; ch.str(c->token()).u32(tid).bytes("abcdefgh", 8);
    CHECK_EQ(c->rawCall(MsgType::UPLOAD_CHUNK, ch, p, off).status, Status::BAD_REQUEST);
    Writer en; en.str(c->token()).u32(tid);
    CHECK_EQ(c->rawCall(MsgType::UPLOAD_END, en, p, off).status, Status::NOT_FOUND);    // session was aborted
    // unknown ids
    Writer c2; c2.str(c->token()).u32(9999).bytes("x", 1);
    CHECK_EQ(c->rawCall(MsgType::UPLOAD_CHUNK, c2, p, off).status, Status::NOT_FOUND);
    Writer d2; d2.str(c->token()).u32(9999);
    CHECK_EQ(c->rawCall(MsgType::DOWNLOAD_CHUNK, d2, p, off).status, Status::NOT_FOUND);
    // incomplete upload
    Writer w3; w3.str(c->token()).str("/").str("short.txt").u64(10).str(Sha256::hashHex("abc")).boolean(false).boolean(false);
    CHECK(c->rawCall(MsgType::UPLOAD_BEGIN, w3, p, off).ok);
    tid = Reader(p.data() + off, p.size() - off).u32();
    Writer c3; c3.str(c->token()).u32(tid).bytes("abc", 3);
    CHECK(c->rawCall(MsgType::UPLOAD_CHUNK, c3, p, off).ok);
    Writer e3; e3.str(c->token()).u32(tid);
    CHECK_EQ(c->rawCall(MsgType::UPLOAD_END, e3, p, off).status, Status::BAD_REQUEST);
    CHECK_EQ(countFiles(e.store() + "/.tmp"), size_t(0));
    // invalid announced checksum format
    Writer w4; w4.str(c->token()).str("/").str("x.txt").u64(1).str("not-a-hash").boolean(false).boolean(false);
    CHECK_EQ(c->rawCall(MsgType::UPLOAD_BEGIN, w4, p, off).status, Status::BAD_REQUEST);
}

TEST(max_file_size_enforced) {
    Env e(1000);  // 1000 byte limit
    auto c = e.client("alice");
    Result r;
    CHECK(!upload(*c, e, "big.bin", std::string(1001, 'x'), "/", false, false, &r));
    CHECK_EQ(r.status, Status::TOO_LARGE);
    CHECK(upload(*c, e, "ok.bin", std::string(1000, 'x')));
}

TEST(path_traversal_prevented) {
    Env e;
    auto c = e.client("alice");
    std::string secret = e.dir + "/secret.txt";
    writeFile(secret, "TOP SECRET");
    std::vector<FileEntry> v; FileEntry fi;
    const char* evil[] = {"/..", "/../", "/../..", "/a/../../etc", "../etc/passwd", "/../secret.txt", "/%2e%2e/x",
                          "/..\\..\\x", "/./../x", "/storage/../../secret.txt"};
    for (const char* p : evil) {
        Status s1 = c->list(p, v).status, s2 = c->info(p, fi).status;
        bool listOk = s1 == Status::INVALID_PATH || s1 == Status::NOT_FOUND;
        bool infoOk = s2 == Status::INVALID_PATH || s2 == Status::NOT_FOUND;
        CHECK(listOk); CHECK(infoOk);
        CHECK(std::string(p).find("..") == std::string::npos || s1 == Status::INVALID_PATH);   // any ".." is rejected outright
        CHECK(c->download(p, e.tmp("stolen")).status != Status::OK);
        CHECK(c->makeDir(std::string(p) + "/x").status != Status::OK);
        CHECK(c->removeFile(p).status != Status::OK);
        CHECK(c->removeDir(p).status != Status::OK);
    }
    CHECK(access(e.tmp("stolen").c_str(), F_OK) != 0);
    CHECK_EQ(readFile(secret), std::string("TOP SECRET"));
    // upload names that try to escape
    writeFile(e.tmp("payload"), "x");
    for (const char* n : {"../escape.txt", "..", "a/b.txt", "/abs.txt", ".hidden", "x\\y", ""}) {
        Result r = c->upload(e.tmp("payload"), "/", n);
        CHECK(!r.ok);
        CHECK_EQ(r.status, Status::INVALID_PATH);
    }
    CHECK(c->upload(e.tmp("payload"), "/../..", "x").status == Status::INVALID_PATH);
    CHECK(access((e.dir + "/escape.txt").c_str(), F_OK) != 0);
    CHECK(access((e.store() + "/../escape.txt").c_str(), F_OK) != 0);
    // rename cannot escape the directory
    CHECK(upload(*c, e, "f.txt", "data"));
    CHECK_EQ(c->rename("/f.txt", "../out.txt").status, Status::INVALID_PATH);
    CHECK_EQ(c->rename("/f.txt", "a/b").status, Status::INVALID_PATH);
    CHECK_EQ(c->rename("/f.txt", "..").status, Status::INVALID_PATH);
    CHECK(access((e.dir + "/out.txt").c_str(), F_OK) != 0);
    // a planted symlink in storage is invisible (not in DB) and never followed
    CHECK(symlink(secret.c_str(), (e.store() + "/planted").c_str()) == 0);
    CHECK_EQ(c->download("/planted", e.tmp("planted.out")).status, Status::NOT_FOUND);
    // rejected attempts are audited
    auto admin = e.client("root1", true, Role::ADMIN);
    std::vector<AuditEntry> a;
    CHECK(admin->audit(200, a).ok);
    bool sawRejected = false;
    for (auto& x : a) if (x.result == "FAILURE" && x.detail.find("rejected path") != std::string::npos) sawRejected = true;
    CHECK(sawRejected);
}

TEST(ownership_and_visibility_rules) {
    Env e;
    auto alice = e.client("alice"), bob = e.client("bob");
    auto fac = e.client("prof", true, Role::FACULTY);
    auto adm = e.client("root1", true, Role::ADMIN);
    CHECK(upload(*alice, e, "private.txt", "alice secret"));
    CHECK(upload(*alice, e, "public.txt", "hello all", "/", true));
    std::vector<FileEntry> v;
    CHECK(bob->list("/", v).ok);
    bool sawPrivate = false, sawPublic = false;
    for (auto& f : v) { if (f.name == "private.txt") sawPrivate = true; if (f.name == "public.txt") sawPublic = true; }
    CHECK(!sawPrivate); CHECK(sawPublic);                                               // students see own + shared only
    CHECK(bob->search("private", v).ok); CHECK(v.empty());                               // search respects visibility
    FileEntry fi;
    CHECK_EQ(bob->info("/private.txt", fi).status, Status::FORBIDDEN);
    CHECK_EQ(bob->download("/private.txt", e.tmp("x1")).status, Status::FORBIDDEN);
    CHECK_EQ(bob->rename("/private.txt", "mine.txt").status, Status::FORBIDDEN);
    CHECK_EQ(bob->removeFile("/private.txt").status, Status::FORBIDDEN);
    CHECK_EQ(bob->setShared("/private.txt", true).status, Status::FORBIDDEN);
    CHECK(bob->download("/public.txt", e.tmp("x2")).ok);                                 // shared: readable
    CHECK_EQ(bob->rename("/public.txt", "stolen.txt").status, Status::FORBIDDEN);        // ...but not modifiable
    CHECK_EQ(bob->removeFile("/public.txt").status, Status::FORBIDDEN);
    CHECK_EQ(upload(*bob, e, "public.txt", "overwrite!", "/", false, true), false);      // cannot overwrite others' files
    CHECK_EQ(readFile(e.store() + "/public.txt"), std::string("hello all"));
    CHECK(alice->setShared("/private.txt", true).ok);                                    // owner can share
    CHECK(bob->download("/private.txt", e.tmp("x3")).ok);
    CHECK(alice->setShared("/private.txt", false).ok);
    CHECK_EQ(bob->download("/private.txt", e.tmp("x4")).status, Status::FORBIDDEN);
    // faculty reads everything but may not delete/rename others' files
    CHECK(fac->download("/private.txt", e.tmp("x5")).ok);
    CHECK_EQ(fac->removeFile("/private.txt").status, Status::FORBIDDEN);
    CHECK_EQ(fac->rename("/private.txt", "z.txt").status, Status::FORBIDDEN);
    // admin may do anything
    CHECK(adm->rename("/private.txt", "renamed-by-admin.txt").ok);
    CHECK(adm->removeFile("/renamed-by-admin.txt").ok);
    // denied attempts are audited
    std::vector<AuditEntry> a;
    CHECK(adm->audit(300, a).ok);
    int denied = 0;
    for (auto& x : a) if (x.result == "DENIED" && x.username == "bob") ++denied;
    CHECK(denied >= 4);
}

TEST(rbac_admin_functions_restricted) {
    Env e;
    auto stu = e.client("stu"), fac = e.client("prof", true, Role::FACULTY);
    std::vector<UserEntry> u; std::vector<AuditEntry> a; KeyValues kv;
    CHECK_EQ(stu->listUsers(u).status, Status::FORBIDDEN);
    CHECK_EQ(stu->audit(10, a).status, Status::FORBIDDEN);
    CHECK_EQ(stu->sysinfo(kv).status, Status::FORBIDDEN);
    CHECK_EQ(stu->setUserRole("stu", "ADMIN").status, Status::FORBIDDEN);                // no self-promotion
    CHECK_EQ(stu->deleteUser("prof").status, Status::FORBIDDEN);
    CHECK_EQ(fac->listUsers(u).status, Status::FORBIDDEN);
    CHECK_EQ(fac->audit(10, a).status, Status::FORBIDDEN);
    CHECK_EQ(fac->setUserRole("stu", "FACULTY").status, Status::FORBIDDEN);
    CHECK(fac->sysinfo(kv).ok);
    CHECK(kv.size() > 10);
    bool sawUptime = false, sawUrandom = false;
    for (auto& p : kv) { if (p.first == "Server uptime") sawUptime = true; if (p.first.find("urandom") != std::string::npos) sawUrandom = true; }
    CHECK(sawUptime); CHECK(sawUrandom);
}

TEST(directories_rename_search_info_delete) {
    Env e;
    auto a = e.client("alice"), b = e.client("bob");
    auto adm = e.client("root1", true, Role::ADMIN);
    CHECK(a->makeDir("/projects").ok);
    CHECK_EQ(a->makeDir("/projects").status, Status::EXISTS);
    CHECK_EQ(a->makeDir("/missing/child").status, Status::NOT_FOUND);
    CHECK(a->makeDir("/projects/2026").ok);
    CHECK(upload(*a, e, "report.txt", "r", "/projects/2026", true));
    CHECK(upload(*a, e, "notes.txt", "n", "/projects"));
    CHECK_EQ(a->makeDir("/projects/notes.txt").status, Status::EXISTS);                  // name clash with a file
    CHECK_EQ(a->upload(e.tmp("up-notes.txt"), "/projects", "2026").status, Status::EXISTS); // file vs dir clash
    CHECK_EQ(a->upload(e.tmp("up-notes.txt"), "/projects/notes.txt", "x").status, Status::INVALID_PATH); // parent is a file
    CHECK_EQ(a->upload(e.tmp("up-notes.txt"), "/nodir", "x").status, Status::NOT_FOUND);
    // real directories exist on disk with restrictive modes
    struct stat st{};
    CHECK(stat((e.store() + "/projects/2026").c_str(), &st) == 0 && S_ISDIR(st.st_mode));
    CHECK_EQ(int(st.st_mode & 0777), 0750);
    // list + info + search
    std::vector<FileEntry> v;
    CHECK(a->list("/projects", v).ok);
    CHECK_EQ(v.size(), size_t(2));
    CHECK(v[0].isDir && v[0].name == "2026");                                            // dirs first
    CHECK(a->search("REPORT", v).ok);                                                    // case-insensitive
    CHECK_EQ(v.size(), size_t(1)); CHECK_EQ(v[0].path, std::string("/projects/2026/report.txt"));
    CHECK(a->search("%", v).ok); CHECK(v.empty());                                       // wildcard chars are literal
    CHECK(a->search("2026", v).ok); CHECK(v.size() >= 1);                                // matches directory name too
    CHECK_EQ(a->search("", v).status, Status::BAD_REQUEST);
    FileEntry fi;
    CHECK(a->info("/projects", fi).ok); CHECK(fi.isDir); CHECK_EQ(fi.owner, std::string("alice"));
    CHECK(a->info("/", fi).ok); CHECK(fi.isDir);
    CHECK_EQ(a->info("/ghost", fi).status, Status::NOT_FOUND);
    // rmdir rules
    CHECK_EQ(a->removeDir("/projects").status, Status::NOT_EMPTY);
    CHECK_EQ(b->removeDir("/projects").status, Status::FORBIDDEN);                       // not owner
    CHECK_EQ(a->removeDir("/").status, Status::INVALID_PATH);
    CHECK_EQ(a->removeDir("/projects/notes.txt").status, Status::INVALID_PATH);          // not a directory
    CHECK_EQ(a->removeFile("/projects").status, Status::INVALID_PATH);                   // rm on a directory
    CHECK_EQ(a->removeDir("/nothing").status, Status::NOT_FOUND);
    // rename a directory: descendants follow, disk follows
    CHECK(a->rename("/projects", "work").ok);
    CHECK(access((e.store() + "/work/2026/report.txt").c_str(), F_OK) == 0);
    CHECK(access((e.store() + "/projects").c_str(), F_OK) != 0);
    CHECK(a->info("/work/2026/report.txt", fi).ok);
    CHECK_EQ(fi.sha256, Sha256::hashHex("r"));
    CHECK_EQ(a->info("/projects/2026/report.txt", fi).status, Status::NOT_FOUND);
    CHECK(a->list("/work/2026", v).ok); CHECK_EQ(v.size(), size_t(1));
    CHECK(a->download("/work/2026/report.txt", e.tmp("rep.out")).ok);
    CHECK_EQ(a->rename("/work", "work").ok, true);                                       // same name is a no-op
    CHECK(a->makeDir("/other").ok);
    CHECK_EQ(a->rename("/other", "work").status, Status::EXISTS);
    CHECK_EQ(a->rename("/ghost", "x").status, Status::NOT_FOUND);
    // rename a file; duplicates refused
    CHECK(a->rename("/work/notes.txt", "n2.txt").ok);
    CHECK_EQ(a->rename("/work/n2.txt", "2026").status, Status::EXISTS);
    // unwinding: delete files, then dirs (admin can remove anyone's dir)
    CHECK(a->removeFile("/work/n2.txt").ok);
    CHECK_EQ(a->removeFile("/work/n2.txt").status, Status::NOT_FOUND);
    CHECK(a->removeFile("/work/2026/report.txt").ok);
    CHECK(access((e.store() + "/work/2026/report.txt").c_str(), F_OK) != 0);
    CHECK(a->removeDir("/work/2026").ok);
    CHECK(adm->removeDir("/work").ok);
    CHECK(access((e.store() + "/work").c_str(), F_OK) != 0);
    CHECK(a->removeDir("/other").ok);
}

TEST(transfer_history_scoping) {
    Env e;
    auto a = e.client("alice"), b = e.client("bob"), fac = e.client("prof", true, Role::FACULTY);
    CHECK(upload(*a, e, "a.txt", "aaa", "/", true));
    CHECK(upload(*b, e, "b.txt", "bbb"));
    CHECK(b->download("/a.txt", e.tmp("h1")).ok);
    std::vector<TransferEntry> h;
    CHECK(a->history(50, h).ok);
    CHECK_EQ(h.size(), size_t(1));                                                       // students: own history only
    CHECK_EQ(h[0].direction, std::string("UPLOAD")); CHECK_EQ(h[0].status, std::string("COMPLETED")); CHECK_EQ(h[0].size, uint64_t(3));
    CHECK_EQ(h[0].sha256, Sha256::hashHex("aaa"));
    CHECK(b->history(50, h).ok); CHECK_EQ(h.size(), size_t(2));
    CHECK(fac->history(50, h).ok); CHECK_EQ(h.size(), size_t(3));                        // faculty: everyone's
    CHECK(fac->history(1, h).ok); CHECK_EQ(h.size(), size_t(1));
    CHECK(h[0].started > 0 && h[0].finished >= h[0].started);
}

TEST(admin_user_management) {
    Env e;
    auto adm = e.client("root1", true, Role::ADMIN);
    auto stu = e.client("stu");
    auto bob = e.client("bob");
    CHECK(upload(*stu, e, "mine.txt", "stu data"));
    std::vector<UserEntry> u;
    CHECK(adm->listUsers(u).ok);
    CHECK_EQ(u.size(), size_t(3));
    // role change applies to live sessions immediately
    KeyValues kv;
    CHECK_EQ(stu->sysinfo(kv).status, Status::FORBIDDEN);
    CHECK(adm->setUserRole("stu", "FACULTY").ok);
    CHECK(stu->sysinfo(kv).ok);
    CHECK(adm->setUserRole("stu", "STUDENT").ok);
    CHECK_EQ(stu->sysinfo(kv).status, Status::FORBIDDEN);
    CHECK_EQ(adm->setUserRole("stu", "ROOT").status, Status::BAD_REQUEST);
    CHECK_EQ(adm->setUserRole("stu", "student").status, Status::BAD_REQUEST);
    CHECK_EQ(adm->setUserRole("ghost", "FACULTY").status, Status::NOT_FOUND);
    CHECK_EQ(adm->setUserRole("root1", "STUDENT").status, Status::FORBIDDEN);            // last admin protected
    CHECK(adm->setUserRole("bob", "ADMIN").ok);
    CHECK(adm->setUserRole("root1", "STUDENT").ok);                                      // now allowed: bob is admin too
    CHECK(bob->setUserRole("root1", "ADMIN").ok);
    // self-delete refused, delete other user: session dies, files reassigned
    CHECK_EQ(adm->deleteUser("root1").status, Status::FORBIDDEN);
    CHECK_EQ(bob->deleteUser("ghost").status, Status::NOT_FOUND);
    CHECK(bob->deleteUser("stu").ok);
    std::vector<FileEntry> v;
    CHECK_EQ(stu->list("/", v).status, Status::AUTH_REQUIRED);
    Client again; CHECK(again.connectTo("127.0.0.1", e.port()).ok);
    CHECK_EQ(again.login("stu", "Password-stu").status, Status::AUTH_FAILED);
    FileEntry fi;
    CHECK(bob->info("/mine.txt", fi).ok); CHECK_EQ(fi.owner, std::string("bob"));       // data preserved, ownership moved
    // audit trail contains the administrative actions
    std::vector<AuditEntry> a;
    CHECK(bob->audit(500, a).ok);
    int roleChanges = 0, deletes = 0;
    for (auto& x : a) { if (x.action == "USER_SET_ROLE" && x.result == "SUCCESS") ++roleChanges; if (x.action == "USER_DELETE") ++deletes; }
    CHECK(roleChanges >= 4); CHECK_EQ(deletes, 1);
    // history of a deleted user is retained
    std::vector<TransferEntry> h;
    CHECK(bob->history(50, h).ok);
    CHECK(!h.empty());
}

TEST(audit_logging_covers_auth_and_files) {
    Env e;
    auto adm = e.client("root1", true, Role::ADMIN);
    auto c = e.client();
    CHECK(c->registerUser("dave", "dave-password").ok);
    CHECK(!c->login("dave", "wrong-pass-1").ok);
    CHECK(c->login("dave", "dave-password").ok);
    CHECK(upload(*c, e, "f.txt", "1"));
    CHECK(c->download("/f.txt", e.tmp("f.out")).ok);
    CHECK(c->rename("/f.txt", "g.txt").ok);
    CHECK(c->makeDir("/d").ok); CHECK(c->removeDir("/d").ok);
    CHECK(c->removeFile("/g.txt").ok);
    CHECK(c->logout().ok);
    std::vector<AuditEntry> a;
    CHECK(adm->audit(500, a).ok);
    auto has = [&](const char* action, const char* result) {
        for (auto& x : a) if (x.action == action && x.result == result && (x.username == "dave" || std::string(action) == "REGISTER")) return true;
        return false;
    };
    for (const char* act : {"REGISTER", "LOGIN", "UPLOAD", "DOWNLOAD", "RENAME", "MKDIR", "RMDIR", "DELETE", "LOGOUT"})
        CHECK(has(act, "SUCCESS"));
    CHECK(has("LOGIN", "FAILURE"));
    CHECK(!a.empty() && !a[0].clientAddr.empty());                                       // client address recorded
    // server log file received entries too
    CHECK(readFile(e.dir + "/server.log").find("AUDIT user=dave action=UPLOAD") != std::string::npos);
}

TEST(malformed_and_hostile_network_input) {
    Env e;
    auto sockTo = [&]() {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons(e.port()); inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        CHECK(connect(fd, (sockaddr*)&sa, sizeof sa) == 0);
        timeval tv{5, 0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        return fd;
    };
    std::string err; Message m;
    {   // garbage bytes: server answers with an error and closes
        int fd = sockTo();
        const char junk[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        CHECK(sendAll(fd, junk, sizeof junk - 1, err));
        CHECK(recvMessage(fd, m, err) == IoResult::OK);
        Reader r(m.payload); CHECK_EQ(r.u16(), uint16_t(Status::BAD_REQUEST));
        CHECK(recvMessage(fd, m, err) == IoResult::CLOSED);
        close(fd);
    }
    {   // header announcing an oversized payload
        int fd = sockTo();
        Header h; h.type = uint16_t(MsgType::PING); h.payloadLen = MAX_PAYLOAD + 1;
        uint8_t buf[HEADER_SIZE]; encodeHeader(h, buf);
        CHECK(sendAll(fd, buf, HEADER_SIZE, err));
        CHECK(recvMessage(fd, m, err) == IoResult::OK);
        CHECK(recvMessage(fd, m, err) == IoResult::CLOSED);
        close(fd);
    }
    {   // truncated frame then disconnect: server must survive
        int fd = sockTo();
        Header h; h.type = uint16_t(MsgType::LOGIN); h.payloadLen = 500;
        uint8_t buf[HEADER_SIZE]; encodeHeader(h, buf);
        CHECK(sendAll(fd, buf, HEADER_SIZE, err));
        CHECK(sendAll(fd, "abc", 3, err));
        close(fd);
    }
    {   // unknown message type and truncated field: BAD_REQUEST, connection stays usable
        int fd = sockTo();
        Message bad; bad.type = 999; bad.requestId = 5;
        CHECK(sendMessage(fd, bad, err));
        CHECK(recvMessage(fd, m, err) == IoResult::OK);
        { Reader r(m.payload); CHECK_EQ(r.u16(), uint16_t(Status::BAD_REQUEST)); CHECK_EQ(m.requestId, 5u); }
        Message trunc; trunc.type = uint16_t(MsgType::LOGIN); trunc.requestId = 6; trunc.payload = {0, 0, 0, 50, 'a'};
        CHECK(sendMessage(fd, trunc, err));
        CHECK(recvMessage(fd, m, err) == IoResult::OK);
        { Reader r(m.payload); CHECK_EQ(r.u16(), uint16_t(Status::BAD_REQUEST)); }
        Message resp; resp.type = uint16_t(MsgType::PING) | RESPONSE_FLAG;                // clients must not send responses
        CHECK(sendMessage(fd, resp, err));
        CHECK(recvMessage(fd, m, err) == IoResult::OK);
        Message ping; ping.type = uint16_t(MsgType::PING); ping.requestId = 7;
        CHECK(sendMessage(fd, ping, err));
        CHECK(recvMessage(fd, m, err) == IoResult::OK);
        { Reader r(m.payload); CHECK_EQ(r.u16(), uint16_t(Status::OK)); CHECK_EQ(m.requestId, 7u); }
        close(fd);
    }
    {   // control characters / overlong input in credentials
        Client c; CHECK(c.connectTo("127.0.0.1", e.port()).ok);
        CHECK(!c.registerUser(std::string("bad\0user", 8), "password123").ok);
        CHECK(!c.login(std::string(5000, 'x'), "p").ok);
        CHECK(c.ping().ok);
    }
    auto c = e.client("ok-user");                                                         // server still healthy
    CHECK(c->ping().ok);
    CHECK(e.srv->services().stats.protocolErrors.load() >= 3);
}

TEST(client_disconnect_mid_transfer_cleans_up) {
    Env e;
    {
        auto c = e.client("alice");
        Writer w; w.str(c->token()).str("/").str("half.bin").u64(100000).str(Sha256::hashHex("x")).boolean(false).boolean(false);
        std::vector<uint8_t> p; size_t off = 0;
        CHECK(c->rawCall(MsgType::UPLOAD_BEGIN, w, p, off).ok);
        uint32_t tid = Reader(p.data() + off, p.size() - off).u32();
        Writer ch; ch.str(c->token()).u32(tid).bytes("partial", 7);
        CHECK(c->rawCall(MsgType::UPLOAD_CHUNK, ch, p, off).ok);
        CHECK_EQ(countFiles(e.store() + "/.tmp"), size_t(1));
    }   // client destroyed -> socket closed abruptly
    for (int i = 0; i < 50 && countFiles(e.store() + "/.tmp") != 0; ++i) std::this_thread::sleep_for(fs_::milliseconds(50));
    CHECK_EQ(countFiles(e.store() + "/.tmp"), size_t(0));
    auto adm = e.client("root1", true, Role::ADMIN);
    std::vector<TransferEntry> h;
    CHECK(adm->history(10, h).ok);
    CHECK(!h.empty() && h[0].status == "ABORTED");
    FileEntry fi;
    CHECK_EQ(adm->info("/half.bin", fi).status, Status::NOT_FOUND);
}

TEST(concurrent_clients) {
    Env e;
    const int N = 12;
    std::atomic<int> failures{0}, completed{0};
    std::vector<std::thread> ts;
    for (int i = 0; i < N; ++i) {
        ts.emplace_back([&, i]() {
            std::string name = "user" + std::to_string(i);
            Client c;
            if (!c.connectTo("127.0.0.1", e.port()).ok) { ++failures; return; }
            if (!c.registerUser(name, "Password-" + name).ok || !c.login(name, "Password-" + name).ok) { ++failures; return; }
            std::string data = randomData(150000 + size_t(i) * 1111), local = e.tmp("cc-" + name), out = e.tmp("cc-out-" + name);
            writeFile(local, data);
            std::string dir = "/dir" + std::to_string(i);
            for (int round = 0; round < 3; ++round) {
                if (round == 0 && !c.makeDir(dir).ok) { ++failures; return; }
                std::string fn = "f" + std::to_string(round) + ".bin";
                if (!c.upload(local, dir, fn, true).ok) { ++failures; return; }
                if (!c.download(dir + "/" + fn, out, true).ok || readFile(out) != data) { ++failures; return; }
                // read somebody else's shared file while others write
                std::vector<FileEntry> v;
                if (!c.search("f0", v).ok) { ++failures; return; }
            }
            std::vector<FileEntry> v;
            if (!c.list(dir, v).ok || v.size() != 3) { ++failures; return; }
            for (auto& f : v) if (!c.removeFile(f.path).ok) { ++failures; return; }
            if (!c.removeDir(dir).ok) { ++failures; return; }
            if (!c.logout().ok) { ++failures; return; }
            ++completed;
        });
    }
    for (auto& t : ts) t.join();
    CHECK_EQ(failures.load(), 0);
    CHECK_EQ(completed.load(), N);
    CHECK_EQ(e.srv->services().stats.uploadsCompleted.load(), uint64_t(N * 3));
    CHECK_EQ(countFiles(e.store() + "/.tmp"), size_t(0));
    auto adm = e.client("root1", true, Role::ADMIN);
    std::vector<TransferEntry> h;
    CHECK(adm->history(500, h).ok);
    CHECK_EQ(h.size(), size_t(N * 6));
    for (auto& t : h) { CHECK(t.status == "COMPLETED"); if (t.status != "COMPLETED") std::printf("   row #%lld %s %s status=%s detail=%s\n", (long long)t.id, t.direction.c_str(), t.path.c_str(), t.status.c_str(), t.detail.c_str()); }
}

TEST(max_clients_limit) {
    char tmpl[] = "/tmp/linsft-it-XXXXXX";
    std::string dir = mkdtemp(tmpl);
    ServerConfig cfg;
    cfg.port = 0; cfg.storageDir = dir + "/s"; cfg.dbPath = dir + "/d.db"; cfg.logPath = dir + "/l.log";
    cfg.pbkdf2Iterations = 1000; cfg.logToConsole = false; cfg.maxClients = 3;
    LinSFTServer srv(cfg);
    std::string err;
    CHECK(srv.start(err));
    std::vector<std::unique_ptr<Client>> keep;
    for (int i = 0; i < 3; ++i) { keep.push_back(std::make_unique<Client>()); CHECK(keep.back()->connectTo("127.0.0.1", srv.port()).ok); CHECK(keep.back()->ping().ok); }
    Client extra;
    CHECK(extra.connectTo("127.0.0.1", srv.port()).ok);
    Result r = extra.ping();
    CHECK(!r.ok);                                                                         // BUSY response or closed connection
    keep.clear();
    srv.stop();
    std::string cmd = "rm -rf " + dir; if (system(cmd.c_str())) {}
}

TEST(graceful_shutdown_with_active_clients) {
    Env e;
    auto a = e.client("alice"), b = e.client("bob");
    // leave an upload in flight
    Writer w; w.str(a->token()).str("/").str("inflight.bin").u64(5000000).str(Sha256::hashHex("x")).boolean(false).boolean(false);
    std::vector<uint8_t> p; size_t off = 0;
    CHECK(a->rawCall(MsgType::UPLOAD_BEGIN, w, p, off).ok);
    uint32_t tid = Reader(p.data() + off, p.size() - off).u32();
    Writer ch; ch.str(a->token()).u32(tid).bytes("abc", 3);
    CHECK(a->rawCall(MsgType::UPLOAD_CHUNK, ch, p, off).ok);
    CHECK(b->ping().ok);
    uint16_t port = e.port();
    auto t0 = fs_::steady_clock::now();
    e.srv->stop();                                                                        // what SIGINT does in main()
    auto ms = fs_::duration_cast<fs_::milliseconds>(fs_::steady_clock::now() - t0).count();
    CHECK(ms < 3000);                                                                     // blocked clients were woken, threads joined
    CHECK(!a->ping().ok);                                                                 // clients observe the closed connection
    CHECK(!b->ping().ok);
    Client late;
    CHECK(!late.connectTo("127.0.0.1", port, 2).ok);                                      // listening socket is closed
    CHECK_EQ(countFiles(e.store() + "/.tmp"), size_t(0));                                 // staging files removed
    auto rows = e.srv->services().db.query("SELECT status FROM transfers WHERE file_path='/inflight.bin'");
    CHECK_EQ(rows.size(), size_t(1));
    CHECK_EQ(DatabaseManager::asStr(rows[0][0]), std::string("ABORTED"));
    CHECK(readFile(e.dir + "/server.log").find("server stopped") != std::string::npos);
}

TEST(persistence_across_restart) {
    Env e;
    {
        auto a = e.client("alice");
        CHECK(a->makeDir("/keep").ok);
        CHECK(upload(*a, e, "kept.txt", "persist me", "/keep"));
    }
    e.srv->stop();
    e.start();                                                                            // same db + storage, new port
    Client c; CHECK(c.connectTo("127.0.0.1", e.port()).ok);
    CHECK(c.login("alice", "Password-alice").ok);                                         // password hashes survived
    CHECK(c.download("/keep/kept.txt", e.tmp("kept.out")).ok);
    CHECK_EQ(readFile(e.tmp("kept.out")), std::string("persist me"));
}

TEST(stale_transfers_recovered_on_startup) {
    Env e;
    e.srv->stop();
    {
        DatabaseManager db; std::string err;
        CHECK(db.open(e.cfg.dbPath, err));
        db.exec("INSERT INTO users(username,salt,pw_hash,iterations,role,created_at) VALUES('ghost','s','h',1,'STUDENT',1)");
        db.exec("INSERT INTO transfers(user_id,username,direction,file_path,status,started_at) VALUES(1,'ghost','UPLOAD','/x','IN_PROGRESS',1)");
    }
    writeFile(e.store() + "/.tmp/up-leftover", "junk");
    e.start();
    auto rows = e.srv->services().db.query("SELECT status FROM transfers WHERE file_path='/x'");
    CHECK_EQ(DatabaseManager::asStr(rows[0][0]), std::string("FAILED"));
    CHECK_EQ(countFiles(e.store() + "/.tmp"), size_t(0));
}

TEST(unicode_and_spaces_in_names) {
    Env e;
    auto c = e.client("alice");
    CHECK(c->makeDir("/Café Menu").ok);
    CHECK(upload(*c, e, "résumé final.txt", "ünïcode", "/Café Menu"));
    CHECK(c->download("/Café Menu/résumé final.txt", e.tmp("u.out")).ok);
    CHECK_EQ(readFile(e.tmp("u.out")), std::string("ünïcode"));
    CHECK(c->rename("/Café Menu", "Ünï Dir").ok);                                         // multi-byte rename + descendant paths
    FileEntry fi;
    CHECK(c->info("/Ünï Dir/résumé final.txt", fi).ok);
}

TEST(default_layout_home_dirs_and_write_rules) {
    Env e;
    auto a = e.client("alice"), b = e.client("bob");
    auto adm = e.client("root1", true, Role::ADMIN);
    std::vector<FileEntry> v;
    CHECK(a->list("/", v).ok);
    for (const char* name : {"public", "documents", "users", "temporary"}) {
        bool found = false;
        for (auto& f : v) if (f.name == name) { found = f.isDir && f.owner == "system"; }
        CHECK(found);                                                                     // default layout exists, system-owned
        struct stat st{};
        CHECK(stat((e.store() + "/" + name).c_str(), &st) == 0 && S_ISDIR(st.st_mode));  // ...as real Linux directories
        CHECK_EQ(int(st.st_mode & 0777), 0750);
    }
    // home directories: created at first login, recorded in users.home_directory
    CHECK(a->list("/users", v).ok);
    int homes = 0;
    for (auto& f : v) if ((f.name == "alice" && f.owner == "alice") || (f.name == "bob" && f.owner == "bob")) ++homes;
    CHECK_EQ(homes, 2);
    auto rows = e.srv->services().db.query("SELECT home_directory FROM users WHERE username='alice'");
    CHECK_EQ(DatabaseManager::asStr(rows[0][0]), std::string("/users/alice"));
    // registration alone also provisions the home directory
    auto reg = e.client();
    CHECK(reg->registerUser("carol", "carol-password").ok);
    FileEntry fi;
    CHECK(a->info("/users/carol", fi).ok); CHECK(fi.isDir); CHECK_EQ(fi.owner, std::string("carol"));
    // private homes: only the owner (or an admin) may create/upload inside
    CHECK_EQ(b->makeDir("/users/alice/x").status, Status::FORBIDDEN);
    CHECK_EQ(b->makeDir("/users/zed").status, Status::FORBIDDEN);
    CHECK_EQ(b->makeDir("/users/bob-extra").status, Status::FORBIDDEN);                  // /users itself is admin-only
    writeFile(e.tmp("h.txt"), "home data");
    CHECK_EQ(b->upload(e.tmp("h.txt"), "/users/alice", "h.txt").status, Status::FORBIDDEN);
    CHECK(a->upload(e.tmp("h.txt"), "/users/alice", "h.txt").ok);
    CHECK(a->makeDir("/users/alice/sub").ok);
    CHECK_EQ(b->download("/users/alice/h.txt", e.tmp("steal")).status, Status::FORBIDDEN);  // files are private by default
    CHECK(adm->makeDir("/users/ghost").ok);                                              // admin may provision homes
    // system directories are protected from ordinary users
    CHECK_EQ(a->removeDir("/public").status, Status::FORBIDDEN);
    CHECK_EQ(a->rename("/documents", "docs2").status, Status::FORBIDDEN);
    // but shared areas are writable by everyone
    CHECK(a->upload(e.tmp("h.txt"), "/documents", "h.txt").ok);
    CHECK(b->upload(e.tmp("h.txt"), "/temporary", "h2.txt").ok);
    std::vector<AuditEntry> au;
    CHECK(adm->audit(300, au).ok);
    int denied = 0;
    for (auto& x : au) if (x.result == "DENIED" && x.username == "bob") ++denied;
    CHECK(denied >= 4);
}

TEST(public_directory_auto_shares_files) {
    Env e;
    auto a = e.client("alice"), b = e.client("bob");
    CHECK(upload(*a, e, "notice.txt", "for everyone", "/public", false));                 // shared flag NOT set by the uploader
    FileEntry fi;
    CHECK(b->info("/public/notice.txt", fi).ok);
    CHECK(fi.shared);
    CHECK(b->download("/public/notice.txt", e.tmp("n.out")).ok);
    CHECK(upload(*a, e, "plain.txt", "private", "/documents", false));                    // other areas stay private by default
    CHECK_EQ(b->download("/documents/plain.txt", e.tmp("p.out")).status, Status::FORBIDDEN);
    CHECK(a->makeDir("/public/sub").ok);
    CHECK(upload(*a, e, "deep.txt", "x", "/public/sub", false));
    CHECK(b->info("/public/sub/deep.txt", fi).ok); CHECK(fi.shared);
}

TEST(file_info_reports_linux_permissions) {
    Env e;
    auto a = e.client("alice");
    CHECK(upload(*a, e, "f.txt", "abc"));
    FileEntry fi;
    CHECK(a->info("/f.txt", fi).ok);
    CHECK(S_ISREG(fi.mode)); CHECK_EQ(int(fi.mode & 07777), 0640);
    CHECK_EQ(modeString(fi.mode), std::string("-rw-r-----"));
    CHECK(a->info("/public", fi).ok);
    CHECK(S_ISDIR(fi.mode)); CHECK_EQ(modeString(fi.mode), std::string("drwxr-x---"));
    CHECK(a->info("/", fi).ok); CHECK(S_ISDIR(fi.mode));
    struct stat st{};                                                                    // what the client sees is what Linux reports
    CHECK(stat((e.store() + "/f.txt").c_str(), &st) == 0);
    CHECK(a->info("/f.txt", fi).ok); CHECK_EQ(int(fi.mode & 07777), int(st.st_mode & 07777));
}

TEST(activity_log_lines_and_search_audit) {
    Env e;
    auto a = e.client("alice"), b = e.client("bob");
    CHECK(upload(*a, e, "f.txt", "abc"));
    CHECK(a->download("/f.txt", e.tmp("f.out")).ok);
    std::vector<FileEntry> v;
    CHECK(a->search("f.txt", v).ok); CHECK_EQ(v.size(), size_t(1));
    CHECK(a->search("nomatchatall", v).ok); CHECK(v.empty());
    CHECK_EQ(b->makeDir("/users/alice/x").status, Status::FORBIDDEN);
    CHECK(a->removeFile("/f.txt").ok);
    CHECK(a->logout().ok);
    std::string log = readFile(e.dir + "/server.log");
    auto has = [&](const char* s) { return log.find(s) != std::string::npos; };
    CHECK(has("[CLIENT] 127.0.0.1:"));
    CHECK(has(" connected (alice)"));
    CHECK(has("[UPLOAD] alice -> /f.txt (3 B) SUCCESS"));
    CHECK(has("[DOWNLOAD] alice <- /f.txt (3 B) SUCCESS"));
    CHECK(has("[SEARCH] alice keyword: f.txt (1 file found)"));
    CHECK(has("[SEARCH] alice keyword: nomatchatall (0 files found)"));
    CHECK(has("[DELETE] alice -> /f.txt SUCCESS"));
    CHECK(has("[DENIED] bob MKDIR /users/alice/x"));
    CHECK(has("logged out (alice)"));
    auto adm = e.client("root1", true, Role::ADMIN);
    std::vector<AuditEntry> au;
    CHECK(adm->audit(300, au).ok);
    bool searchAudited = false;
    for (auto& x : au) if (x.action == "SEARCH" && x.target == "f.txt" && x.detail == "1 file found") searchAudited = true;
    CHECK(searchAudited);                                                                 // searches are also in the DB audit trail
}


int main() { return tf::runAll("integration"); }
