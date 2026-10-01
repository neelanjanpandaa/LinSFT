// GUI tests: real Qt widgets (offscreen platform) driving a real client against a real in-process server.
#include <QApplication>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include "linsft/crypto.h"
#include "linsft/server.h"
#include "login_dialog.h"
#include "main_window.h"
#include "test_framework.h"

using namespace linsft;

struct GuiEnv {
    std::string dir;
    ServerConfig cfg;
    std::unique_ptr<LinSFTServer> srv;
    GuiEnv() {
        char tmpl[] = "/tmp/linsft-gui-XXXXXX";
        dir = mkdtemp(tmpl);
        cfg.port = 0; cfg.storageDir = dir + "/storage"; cfg.dbPath = dir + "/db.sqlite"; cfg.logPath = dir + "/log";
        cfg.pbkdf2Iterations = 1000; cfg.logToConsole = false;
        srv = std::make_unique<LinSFTServer>(cfg);
        std::string err;
        if (!srv->start(err)) { std::printf("server: %s\n", err.c_str()); std::abort(); }
    }
    ~GuiEnv() { srv->stop(); srv.reset(); std::string c = "rm -rf " + dir; if (system(c.c_str())) {} }
    void user(const std::string& n, Role r) { std::string m; srv->services().auth.createOrUpdateUser(n, "Password-" + n, r, m); }
    bool login(Client& c, const std::string& n) {
        return c.connectTo("127.0.0.1", srv->port()).ok && c.login(n, "Password-" + n).ok;
    }
    std::string file(const std::string& name, const std::string& data) {
        std::string p = dir + "/" + name; std::ofstream(p, std::ios::binary) << data; return p;
    }
};

static QStringList tabNames(MainWindow& w) { QStringList l; for (int i = 0; i < w.tabs()->count(); ++i) l << w.tabs()->tabText(i); return l; }
static QStringList buttonTexts(MainWindow& w) { QStringList l; for (auto* b : w.actionButtons()) l << b->text(); return l; }
static int rowOf(QTableWidget* t, const QString& name) {
    for (int r = 0; r < t->rowCount(); ++r) if (t->item(r, 0) && t->item(r, 0)->text().startsWith(name)) return r;
    return -1;
}

TEST(login_dialog_flows) {
    GuiEnv e; e.user("alice", Role::STUDENT);
    Client c;
    LoginDialog d(c, "127.0.0.1", e.srv->port());
    d.setInteractive(false);
    CHECK(!d.doLogin("", ""));
    CHECK(!d.doLogin("alice", "wrong-password"));
    CHECK(d.lastMessage().contains("invalid credentials"));
    CHECK(!d.doRegister("newbie", "password-one", "password-two"));      // mismatch caught client-side
    CHECK(d.lastMessage().contains("do not match"));
    CHECK(!d.doRegister("alice", "password-one", "password-one"));       // duplicate
    CHECK(d.doRegister("newbie", "password-one", "password-one"));       // registers and signs in
    CHECK(c.loggedIn()); CHECK(c.role() == Role::STUDENT);
    Client c2;
    LoginDialog d2(c2, "127.0.0.1", 1);                                  // nothing listens there
    CHECK(!d2.doLogin("alice", "Password-alice"));
    CHECK(d2.lastMessage().contains("running"));
}

TEST(student_dashboard_all_actions) {
    GuiEnv e; e.user("alice", Role::STUDENT); e.user("bob", Role::STUDENT);
    Client c; CHECK(e.login(c, "alice"));
    MainWindow w(c, "test:0"); w.setInteractive(false); w.show();
    CHECK_EQ(tabNames(w), QStringList({"Files", "Transfer History"}));   // admin/faculty tabs not offered to students
    QStringList bt = buttonTexts(w);
    for (const char* t : {"Upload", "Download", "File Info", "Rename", "Delete", "Share / Unshare", "New Folder", "Remove Folder", "Refresh"}) CHECK(bt.contains(t));
    CHECK(!bt.contains("Change Role")); CHECK(!bt.contains("Delete User"));
    CHECK(!w.button("Download")->isEnabled());                           // nothing selected -> disabled
    CHECK(!w.button("Delete")->isEnabled());

    CHECK(w.makeFolder("Docs"));
    CHECK(rowOf(w.fileTable(), "Docs") >= 0);
    CHECK(w.openDir("/Docs"));
    CHECK_EQ(w.currentPath(), QString("/Docs"));
    std::string data(300000, 'q'); for (size_t i = 0; i < data.size(); i += 7) data[i] = char('a' + i % 26);
    CHECK(w.uploadFile(QString::fromStdString(e.file("report.txt", data)), false, false));
    int r = rowOf(w.fileTable(), "report.txt");
    CHECK(r >= 0);
    w.selectRow(r);
    CHECK(w.button("Download")->isEnabled()); CHECK(w.button("Delete")->isEnabled()); CHECK(w.button("Rename")->isEnabled());
    CHECK(w.button("Share / Unshare")->isEnabled()); CHECK(w.button("File Info")->isEnabled());
    CHECK(!w.button("Remove Folder")->isEnabled());                      // a file is selected
    CHECK(w.infoText("/Docs/report.txt").contains(QString::fromStdString(Sha256::hashHex(data))));
    QString out = QString::fromStdString(e.dir + "/dl.txt");
    CHECK(w.downloadTo("/Docs/report.txt", out, true));
    { std::ifstream f(out.toStdString(), std::ios::binary); std::stringstream ss; ss << f.rdbuf(); CHECK(ss.str() == data); }
    CHECK(w.toggleShare("/Docs/report.txt"));
    CHECK_EQ(w.fileTable()->item(rowOf(w.fileTable(), "report.txt"), 4)->text(), QString("Yes"));
    CHECK(w.toggleShare("/Docs/report.txt"));
    CHECK(w.renameEntry("/Docs/report.txt", "final.txt"));
    CHECK(rowOf(w.fileTable(), "final.txt") >= 0); CHECK(rowOf(w.fileTable(), "report.txt") < 0);
    CHECK(w.searchFor("FINAL"));
    CHECK_EQ(w.fileTable()->rowCount(), 1);
    CHECK(w.fileTable()->item(0, 0)->text().contains("/Docs/final.txt"));
    w.button("Clear")->click();                                          // clear search -> back to directory listing
    CHECK(rowOf(w.fileTable(), "final.txt") >= 0);
    w.button("Up")->click();
    CHECK_EQ(w.currentPath(), QString("/"));
    int dr = rowOf(w.fileTable(), "Docs"); w.selectRow(dr);
    CHECK(w.button("Remove Folder")->isEnabled()); CHECK(!w.button("Download")->isEnabled());
    CHECK(!w.removeFolder("/Docs"));                                     // not empty -> server refuses, message shown
    CHECK(w.lastMessage().contains("not empty"));
    CHECK(w.openDir("/Docs"));
    CHECK(w.deleteFile("/Docs/final.txt"));
    CHECK(w.openDir("/"));
    CHECK(w.removeFolder("/Docs"));
    CHECK_EQ(rowOf(w.fileTable(), "Docs"), -1);
    CHECK(w.refreshHistory());
    CHECK_EQ(w.historyTable()->rowCount(), 2);                           // 1 upload + 1 download
    CHECK_EQ(w.historyTable()->item(0, 5)->text(), QString("COMPLETED"));
    CHECK(!w.openDir("/nonexistent"));                                   // error path keeps the old directory
    CHECK_EQ(w.currentPath(), QString("/"));
    w.grab().save("/tmp/linsft_gui_student.png");
    w.logout();
    CHECK(w.loggedOut()); CHECK(!c.connected());
}

TEST(student_cannot_modify_others_in_ui) {
    GuiEnv e; e.user("alice", Role::STUDENT); e.user("bob", Role::STUDENT);
    Client a; CHECK(e.login(a, "alice"));
    MainWindow wa(a, "t"); wa.setInteractive(false);
    CHECK(wa.uploadFile(QString::fromStdString(e.file("shared.txt", "hi")), true, false));
    Client b; CHECK(e.login(b, "bob"));
    MainWindow wb(b, "t"); wb.setInteractive(false);
    int r = rowOf(wb.fileTable(), "shared.txt");
    CHECK(r >= 0);
    wb.selectRow(r);
    CHECK(wb.button("Download")->isEnabled());                           // can read a shared file
    CHECK(!wb.button("Delete")->isEnabled());                            // ...but cannot delete / rename / share it
    CHECK(!wb.button("Rename")->isEnabled());
    CHECK(!wb.button("Share / Unshare")->isEnabled());
    CHECK(!wb.deleteFile("/shared.txt"));                                // even if forced, the server says no
    CHECK(wb.lastMessage().contains("permission denied"));
}

TEST(faculty_dashboard) {
    GuiEnv e; e.user("prof", Role::FACULTY);
    Client c; CHECK(e.login(c, "prof"));
    MainWindow w(c, "t"); w.setInteractive(false);
    CHECK_EQ(tabNames(w), QStringList({"Files", "Transfer History", "System Monitor"}));
    CHECK(w.refreshSystem());
    CHECK(w.systemTable()->rowCount() > 10);
    CHECK(!w.refreshUsers());                                            // not permitted: nothing happens
    w.grab().save("/tmp/linsft_gui_faculty.png");
}

TEST(admin_dashboard_user_management) {
    GuiEnv e; e.user("root1", Role::ADMIN); e.user("victim", Role::STUDENT);
    Client c; CHECK(e.login(c, "root1"));
    MainWindow w(c, "t"); w.setInteractive(false); w.show();
    CHECK_EQ(tabNames(w), QStringList({"Files", "Transfer History", "System Monitor", "Users", "Audit Log"}));
    QStringList bt = buttonTexts(w);
    CHECK(bt.contains("Change Role")); CHECK(bt.contains("Delete User"));
    CHECK(w.refreshUsers());
    CHECK_EQ(w.usersTable()->rowCount(), 2);
    CHECK(w.changeUserRole("victim", "FACULTY"));
    bool found = false;
    for (int r = 0; r < w.usersTable()->rowCount(); ++r)
        if (w.usersTable()->item(r, 1)->text() == "victim") found = w.usersTable()->item(r, 2)->text() == "FACULTY";
    CHECK(found);
    CHECK(!w.changeUserRole("root1", "STUDENT"));                        // last admin protected
    CHECK(w.lastMessage().contains("last administrator"));
    CHECK(!w.removeUser("root1"));                                       // cannot delete self
    w.usersTable()->selectRow(0);
    CHECK(!w.button("Delete User")->isEnabled());                        // row 0 is root1 (self): button disabled
    w.usersTable()->selectRow(1);
    CHECK(w.button("Delete User")->isEnabled());
    CHECK(w.removeUser("victim"));
    CHECK_EQ(w.usersTable()->rowCount(), 1);
    CHECK(w.refreshAudit());
    CHECK(w.auditTable()->rowCount() >= 3);
    CHECK(w.refreshSystem());
    w.tabs()->setCurrentIndex(3);                                        // switching tabs triggers a refresh
    w.grab().save("/tmp/linsft_gui_admin_users.png");
    w.tabs()->setCurrentIndex(0);
}

TEST(session_loss_logs_out_gui) {
    GuiEnv e; e.user("alice", Role::STUDENT);
    Client c; CHECK(e.login(c, "alice"));
    MainWindow w(c, "t"); w.setInteractive(false);
    bool signalled = false;
    QObject::connect(&w, &MainWindow::loggedOutSignal, [&]() { signalled = true; });
    e.srv->stop();                                                       // server disappears
    CHECK(!w.refresh());
    CHECK(signalled); CHECK(w.loggedOut());
}

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    return tf::runAll("gui");
}
