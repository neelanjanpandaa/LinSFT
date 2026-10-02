// Unit tests: crypto vectors, protocol framing, path validation, RBAC matrix, SQLite layer.
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>

#include "linsft/crypto.h"
#include "linsft/database.h"
#include "linsft/models.h"
#include "linsft/pathutil.h"
#include "linsft/permissions.h"
#include "linsft/protocol.h"
#include "test_framework.h"

using namespace linsft;

TEST(sha256_known_vectors) {
    CHECK_EQ(Sha256::hashHex(""), std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(Sha256::hashHex("abc"), std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(Sha256::hashHex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
             std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    Sha256 h;  // streaming in odd-sized pieces must equal one-shot
    std::string million(1000000, 'a');
    for (size_t i = 0; i < million.size(); i += 777) h.update(million.data() + i, std::min<size_t>(777, million.size() - i));
    CHECK_EQ(toHex(h.finish()), std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

TEST(hmac_and_pbkdf2_vectors) {
    std::vector<uint8_t> key(20, 0x0b);
    HmacSha256 mac(key.data(), key.size());
    std::string msg = "Hi There";
    CHECK_EQ(toHex(mac.compute(reinterpret_cast<const uint8_t*>(msg.data()), msg.size())),
             std::string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    auto dk = pbkdf2HmacSha256("passwd", reinterpret_cast<const uint8_t*>("salt"), 4, 1, 64);
    CHECK_EQ(toHex(dk.data(), dk.size()),
             std::string("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"));
}

TEST(random_and_hex) {
    std::string a = randomHex(32), b = randomHex(32);
    CHECK_EQ(a.size(), size_t(64));
    CHECK(a != b);
    std::vector<uint8_t> v;
    CHECK(fromHex("00ff10", v));
    CHECK_EQ(v.size(), size_t(3));
    CHECK(!fromHex("0g", v));
    CHECK(!fromHex("abc", v));
    CHECK(constantTimeEquals("abc", "abc"));
    CHECK(!constantTimeEquals("abc", "abd"));
}

TEST(protocol_writer_reader_roundtrip) {
    Writer w;
    w.u8(7).u16(0xBEEF).u32(0xDEADBEEF).u64(0x0102030405060708ULL).i64(-5).boolean(true).str("héllo");
    Reader r(w.data());
    CHECK_EQ(r.u8(), uint8_t(7));
    CHECK_EQ(r.u16(), uint16_t(0xBEEF));
    CHECK_EQ(r.u32(), uint32_t(0xDEADBEEF));
    CHECK_EQ(r.u64(), uint64_t(0x0102030405060708ULL));
    CHECK_EQ(r.i64(), int64_t(-5));
    CHECK(r.boolean());
    CHECK_EQ(r.str(), std::string("héllo"));
    r.expectEnd();
}

TEST(protocol_reader_rejects_malformed) {
    std::vector<uint8_t> shortBuf = {0, 0, 0, 10, 'a'};  // claims 10 bytes, has 1
    bool threw = false;
    try { Reader r(shortBuf); r.str(); } catch (const ProtocolError&) { threw = true; }
    CHECK(threw);
    Writer w; w.str(std::string(100, 'x'));
    threw = false;
    try { Reader r(w.data()); r.str(50); } catch (const ProtocolError&) { threw = true; }  // over max length
    CHECK(threw);
    threw = false;
    try { Reader r(std::vector<uint8_t>{}); r.u32(); } catch (const ProtocolError&) { threw = true; }
    CHECK(threw);
}

TEST(protocol_header_validation) {
    Header h; h.type = uint16_t(MsgType::LOGIN); h.requestId = 42; h.payloadLen = 100;
    uint8_t buf[HEADER_SIZE];
    encodeHeader(h, buf);
    CHECK_EQ(buf[0], uint8_t('L'));  // magic is "LSFT" on the wire
    CHECK_EQ(buf[3], uint8_t('T'));
    Header d; std::string err;
    CHECK(decodeHeader(buf, d, err));
    CHECK_EQ(d.type, h.type); CHECK_EQ(d.requestId, 42u); CHECK_EQ(d.payloadLen, 100u);
    buf[0] = 'X';
    CHECK(!decodeHeader(buf, d, err));          // bad magic
    encodeHeader(h, buf); buf[4] = 9;
    CHECK(!decodeHeader(buf, d, err));          // bad version
    h.payloadLen = MAX_PAYLOAD + 1; encodeHeader(h, buf);
    CHECK(!decodeHeader(buf, d, err));          // oversize payload
    h.payloadLen = MAX_PAYLOAD; encodeHeader(h, buf);
    CHECK(decodeHeader(buf, d, err));           // exactly at the limit is fine
}

TEST(protocol_message_over_socketpair) {
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    Writer body; body.str("payload").u32(99);
    Message m = makeRequest(MsgType::SEARCH, 1234, body);
    std::string err;
    CHECK(sendMessage(sv[0], m, err));
    Message got;
    CHECK(recvMessage(sv[1], got, err) == IoResult::OK);
    CHECK_EQ(got.type, uint16_t(MsgType::SEARCH));
    CHECK_EQ(got.requestId, 1234u);
    CHECK(got.payload == m.payload);
    // garbage -> PROTOCOL
    const char junk[16] = "NOTLSFTNOTLSFT!";
    CHECK(sendAll(sv[0], junk, 16, err));
    CHECK(recvMessage(sv[1], got, err) == IoResult::PROTOCOL);
    // truncated frame then close -> ERROR (not a clean close)
    int sv2[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
    auto frame = encodeMessage(m);
    CHECK(sendAll(sv2[0], frame.data(), frame.size() - 3, err));
    close(sv2[0]);
    CHECK(recvMessage(sv2[1], got, err) == IoResult::ERROR);
    // clean close at a boundary -> CLOSED
    int sv3[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv3) == 0);
    close(sv3[0]);
    CHECK(recvMessage(sv3[1], got, err) == IoResult::CLOSED);
    close(sv[0]); close(sv[1]); close(sv2[1]); close(sv3[1]);
}

TEST(protocol_response_and_models) {
    FileEntry e; e.id = 5; e.path = "/a/b.txt"; e.name = "b.txt"; e.size = 123456789012ULL; e.owner = "bob";
    e.sha256 = std::string(64, 'a'); e.shared = true; e.created = 1; e.modified = 2;
    Writer body; writeList(body, std::vector<FileEntry>{e, e});
    Message resp = makeResponse(uint16_t(MsgType::LIST), 9, Status::OK, "ok", &body);
    CHECK_EQ(resp.type, uint16_t(uint16_t(MsgType::LIST) | RESPONSE_FLAG));
    Reader r(resp.payload);
    CHECK_EQ(r.u16(), uint16_t(Status::OK));
    CHECK_EQ(r.str(), std::string("ok"));
    CHECK_EQ(r.u32(), 2u);
    FileEntry back = readFileEntry(r);
    CHECK_EQ(back.path, e.path); CHECK_EQ(back.size, e.size); CHECK(back.shared);
}

TEST(path_validation_blocks_traversal) {
    std::string out;
    CHECK(normalizeVirtualPath("/", out)); CHECK_EQ(out, std::string("/"));
    CHECK(normalizeVirtualPath("/a//b/./c", out)); CHECK_EQ(out, std::string("/a/b/c"));
    const char* bad[] = {"", "relative/path", "/../etc/passwd", "/a/../../etc", "/a/..", "..", "/a/b/../c",
                         "/a\\b", "/.hidden", "/a/.ssh", "/a\x01z", "/ends/with/space ", "/\x7f"};
    for (const char* b : bad) CHECK(!normalizeVirtualPath(b, out));
    CHECK(!normalizeVirtualPath(std::string("/a") + std::string(1, '\0') + "b", out));
    CHECK(!normalizeVirtualPath("/" + std::string(2000, 'x'), out));
    CHECK(!normalizeVirtualPath("/" + std::string(300, 'x'), out));  // component > 255
    CHECK_EQ(parentOf("/a/b"), std::string("/a")); CHECK_EQ(parentOf("/a"), std::string("/"));
    CHECK_EQ(baseName("/a/b"), std::string("b")); CHECK_EQ(joinPath("/", "x"), std::string("/x"));
    CHECK_EQ(joinPath("/a", "x"), std::string("/a/x"));
}

TEST(name_user_password_validation) {
    CHECK(isValidName("report v2.pdf")); CHECK(!isValidName("a/b")); CHECK(!isValidName("..")); CHECK(!isValidName(""));
    CHECK(!isValidName(".bashrc")); CHECK(!isValidName("x\ny"));
    CHECK(isValidUsername("alice_01")); CHECK(!isValidUsername("ab")); CHECK(!isValidUsername("bad name"));
    CHECK(!isValidUsername("a'; DROP TABLE users;--"));
    CHECK(isValidPassword("longenough")); CHECK(!isValidPassword("short"));
    CHECK(isValidSha256Hex(std::string(64, 'f'))); CHECK(!isValidSha256Hex(std::string(64, 'G'))); CHECK(!isValidSha256Hex("abc"));
}

TEST(rbac_matrix) {
    for (Perm p : {Perm::UPLOAD, Perm::DOWNLOAD, Perm::LIST, Perm::SEARCH, Perm::INFO, Perm::RENAME_OWN, Perm::DELETE_OWN,
                   Perm::MKDIR, Perm::RMDIR_OWN, Perm::VIEW_OWN_HISTORY})
        for (Role r : {Role::STUDENT, Role::FACULTY, Role::ADMIN}) CHECK(PermissionService::has(r, p));
    for (Perm p : {Perm::READ_ALL_FILES, Perm::VIEW_ALL_HISTORY, Perm::VIEW_SYSTEM}) {
        CHECK(!PermissionService::has(Role::STUDENT, p)); CHECK(PermissionService::has(Role::FACULTY, p)); CHECK(PermissionService::has(Role::ADMIN, p));
    }
    for (Perm p : {Perm::RENAME_ANY, Perm::DELETE_ANY, Perm::RMDIR_ANY, Perm::MANAGE_USERS, Perm::VIEW_AUDIT}) {
        CHECK(!PermissionService::has(Role::STUDENT, p)); CHECK(!PermissionService::has(Role::FACULTY, p)); CHECK(PermissionService::has(Role::ADMIN, p));
    }
    Principal stu{1, "s", Role::STUDENT}, fac{2, "f", Role::FACULTY}, adm{3, "a", Role::ADMIN};
    CHECK(PermissionService::canReadFile(stu, 1, false));   // own private
    CHECK(!PermissionService::canReadFile(stu, 2, false));  // someone else's private
    CHECK(PermissionService::canReadFile(stu, 2, true));    // shared
    CHECK(PermissionService::canReadFile(fac, 1, false));   // faculty reads all
    CHECK(PermissionService::canDeleteFile(stu, 1)); CHECK(!PermissionService::canDeleteFile(stu, 2));
    CHECK(!PermissionService::canDeleteFile(fac, 1)); CHECK(PermissionService::canDeleteFile(adm, 1));
    CHECK(PermissionService::canRename(stu, 1)); CHECK(!PermissionService::canRename(stu, 9)); CHECK(PermissionService::canRename(adm, 9));
    CHECK(!PermissionService::canRemoveDir(stu, 9)); CHECK(PermissionService::canRemoveDir(adm, 9));
    Role rr; CHECK(parseRole("FACULTY", rr)); CHECK(rr == Role::FACULTY); CHECK(!parseRole("ROOT", rr)); CHECK(!parseRole("student", rr));
}

TEST(sqlite_prepared_statements_and_injection) {
    char tmpl[] = "/tmp/linsft-unit-XXXXXX";
    int fd = mkstemp(tmpl); close(fd);
    DatabaseManager db; std::string err;
    CHECK(db.open(tmpl, err));
    std::string evil = "x'); DROP TABLE users; --";
    db.exec("INSERT INTO users(username,salt,pw_hash,iterations,role,created_at) VALUES(?,?,?,?,?,?)",
            {evil, std::string("s"), std::string("h"), int64_t(1), std::string("STUDENT"), int64_t(1)});
    auto rows = db.query("SELECT username FROM users WHERE username=?", {evil});
    CHECK_EQ(rows.size(), size_t(1));
    CHECK_EQ(DatabaseManager::asStr(rows[0][0]), evil);                 // stored literally, table intact
    CHECK_EQ(db.query("SELECT COUNT(*) FROM users")[0][0], DatabaseManager::Value(int64_t(1)));
    bool constraint = false;                                              // UNIQUE + case-insensitive
    try { db.exec("INSERT INTO users(username,salt,pw_hash,iterations,role,created_at) VALUES(?,?,?,?,?,?)",
                  {std::string("X'); DROP TABLE USERS; --"), std::string("s"), std::string("h"), int64_t(1), std::string("STUDENT"), int64_t(1)}); }
    catch (const DbError& e) { constraint = e.isConstraint(); }
    CHECK(constraint);
    bool badRole = false;                                                 // CHECK constraint on role
    try { db.exec("INSERT INTO users(username,salt,pw_hash,iterations,role,created_at) VALUES('z','s','h',1,'ROOT',1)"); }
    catch (const DbError& e) { badRole = e.isConstraint(); }
    CHECK(badRole);
    {   // transaction rollback
        DatabaseManager::Transaction tx(db);
        db.exec("DELETE FROM users");
    }
    CHECK_EQ(DatabaseManager::asInt(db.query("SELECT COUNT(*) FROM users")[0][0]), int64_t(1));
    {   // commit
        DatabaseManager::Transaction tx(db);
        db.exec("DELETE FROM users");
        tx.commit();
    }
    CHECK_EQ(DatabaseManager::asInt(db.query("SELECT COUNT(*) FROM users")[0][0]), int64_t(0));
    bool syntax = false;
    try { db.query("SELEKT 1"); } catch (const DbError&) { syntax = true; }
    CHECK(syntax);
    for (const char* t : {"users", "files", "transfers", "audit_logs", "directories"})
        CHECK_EQ(db.query("SELECT name FROM sqlite_master WHERE type='table' AND name=?", {std::string(t)}).size(), size_t(1));
    db.close();
    unlink(tmpl); unlink((std::string(tmpl) + "-wal").c_str()); unlink((std::string(tmpl) + "-shm").c_str());
}

#include "linsft/server.h"

TEST(shipped_config_file_parses) {
    ServerConfig c;
    std::string err;
    CHECK(c.loadFile(std::string(LINSFT_SOURCE_DIR) + "/config/server.conf", err));  // the file users actually get
    CHECK_EQ(c.bindAddress, std::string("127.0.0.1"));
    CHECK_EQ(c.port, uint16_t(5000));
    CHECK_EQ(c.storageDir, std::string("server_storage"));
    CHECK_EQ(c.dbPath, std::string("database/file_sharing.db"));
    CHECK_EQ(c.maxFileSize, uint64_t(536870912));
    CHECK_EQ(c.pbkdf2Iterations, 100000u);
    char tmpl[] = "/tmp/linsft-cfg-XXXXXX";
    int fd = mkstemp(tmpl);
    const char* bad = "port = 99999\n";
    CHECK(write(fd, bad, strlen(bad)) > 0);
    close(fd);
    ServerConfig d;
    CHECK(!d.loadFile(tmpl, err));                      // invalid value is reported, not ignored
    CHECK(err.find("port") != std::string::npos);
    ServerConfig e2;
    CHECK(!e2.loadFile("/nonexistent/file.conf", err));
    unlink(tmpl);
}

#include "linsft/user.h"

TEST(oop_user_hierarchy_polymorphism) {
    Principal sp{1, "stu", Role::STUDENT}, fp{2, "fac", Role::FACULTY}, ap{3, "adm", Role::ADMIN};
    std::unique_ptr<User> s = User::create(sp), f = User::create(fp), a = User::create(ap);
    CHECK(dynamic_cast<Student*>(s.get()) != nullptr);
    CHECK(dynamic_cast<Faculty*>(f.get()) != nullptr);
    CHECK(dynamic_cast<Admin*>(a.get()) != nullptr);
    CHECK_EQ(std::string(s->title()), std::string("Student"));
    CHECK_EQ(std::string(a->title()), std::string("Admin"));
    // canDelete() is virtual: same call, role-specific behaviour
    CHECK(s->canDelete(1));  CHECK(!s->canDelete(2));
    CHECK(f->canDelete(2));  CHECK(!f->canDelete(1));
    CHECK(a->canDelete(1));  CHECK(a->canDelete(2)); CHECK(a->canDelete(99));
    CHECK(!s->isLoggedIn()); s->login(); CHECK(s->isLoggedIn()); s->logout(); CHECK(!s->isLoggedIn());
    CHECK_EQ(s->id(), int64_t(1)); CHECK_EQ(s->username(), std::string("stu")); CHECK(s->role() == Role::STUDENT);
    // PermissionService delegates to the hierarchy, so both views agree
    for (Principal p : {sp, fp, ap})
        for (int64_t owner : {int64_t(1), int64_t(2), int64_t(3), int64_t(99)})
            CHECK_EQ(PermissionService::canDeleteFile(p, owner), User::create(p)->canDelete(owner));
}

TEST(storage_layout_write_rules) {
    Principal alice{1, "alice", Role::STUDENT}, bob{2, "Bob", Role::STUDENT}, adm{3, "root", Role::ADMIN};
    CHECK(PermissionService::canWriteInto(alice, "/"));
    CHECK(PermissionService::canWriteInto(alice, "/public"));
    CHECK(PermissionService::canWriteInto(alice, "/documents/sub"));
    CHECK(PermissionService::canWriteInto(alice, "/users/alice"));
    CHECK(PermissionService::canWriteInto(alice, "/users/ALICE/sub"));      // names are case-insensitive like usernames
    CHECK(!PermissionService::canWriteInto(alice, "/users/bob"));
    CHECK(!PermissionService::canWriteInto(alice, "/users/bob/x"));
    CHECK(!PermissionService::canWriteInto(alice, "/users"));
    CHECK(!PermissionService::canWriteInto(bob, "/users/alice"));
    CHECK(PermissionService::canWriteInto(bob, "/users/bob"));
    CHECK(PermissionService::canWriteInto(adm, "/users/alice"));
    CHECK(PermissionService::canWriteInto(adm, "/users"));
    CHECK(PermissionService::isPublicPath("/public")); CHECK(PermissionService::isPublicPath("/public/a/b"));
    CHECK(!PermissionService::isPublicPath("/publication")); CHECK(!PermissionService::isPublicPath("/documents"));
    CHECK(!PermissionService::isPublicPath("/users/public"));
}

TEST(file_mode_formatting_and_username_rules) {
    CHECK_EQ(modeString(S_IFREG | 0640), std::string("-rw-r-----"));
    CHECK_EQ(modeString(S_IFDIR | 0750), std::string("drwxr-x---"));
    CHECK_EQ(modeString(S_IFREG | 0777), std::string("-rwxrwxrwx"));
    CHECK_EQ(modeOctal(S_IFREG | 0640), std::string("0640"));
    CHECK(!isValidUsername(".hidden")); CHECK(!isValidUsername("-dash")); CHECK(!isValidUsername("_u_s"));  // must start alphanumeric
    CHECK(isValidUsername("a.b-c_d")); CHECK(isValidUsername("9lives"));
    FileEntry e; e.mode = S_IFREG | 0640; e.path = "/x"; e.name = "x";
    Writer w; write(w, e);
    Reader r(w.data());
    CHECK_EQ(readFileEntry(r).mode, uint32_t(S_IFREG | 0640));            // mode survives the wire format
}


int main() { return tf::runAll("unit"); }
