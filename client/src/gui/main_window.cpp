#include "main_window.h"

#include <QApplication>
#include <QCloseEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QMessageBox>
#include <QProgressDialog>
#include <QPushButton>
#include <QStatusBar>
#include <QStyle>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

using namespace linsft;

static QString q(const std::string& s) { return QString::fromStdString(s); }

MainWindow::MainWindow(Client& client, const QString& serverLabel, QWidget* parent)
    : QMainWindow(parent), client_(client) {
    setWindowTitle("LinSFT - Secure File Transfer");
    resize(1040, 640);
    const Principal p = me();

    // ---- menu ----
    QMenu* session = menuBar()->addMenu("&Session");
    QAction* actLogout = session->addAction("&Logout");
    QAction* actQuit = session->addAction("&Quit");
    connect(actLogout, &QAction::triggered, this, &MainWindow::logout);
    connect(actQuit, &QAction::triggered, qApp, &QApplication::quit);
    QMenu* helpMenu = menuBar()->addMenu("&Help");
    connect(helpMenu->addAction("&About"), &QAction::triggered, this, [this]() {
        QMessageBox::about(this, "About LinSFT",
                           "<b>LinSFT</b> - Linux Secure File Transfer and System Monitoring Platform<br>"
                           "C++17 / POSIX sockets / SQLite / Qt6. Files are verified end-to-end with SHA-256.");
    });

    auto* central = new QWidget;
    auto* root = new QVBoxLayout(central);
    setCentralWidget(central);

    // ---- header ----
    auto* head = new QHBoxLayout;
    whoLabel_ = new QLabel(QString("<b>%1</b> &nbsp;<span style='color:#1565c0'>[%2]</span> &nbsp;<span style='color:gray'>%3</span>")
                               .arg(q(p.username), roleName(p.role), serverLabel));
    head->addWidget(whoLabel_);
    head->addStretch();
    auto* logoutBtn = new QPushButton(style()->standardIcon(QStyle::SP_DialogCloseButton), "Logout");
    logoutBtn->setToolTip("End your session and return to the login screen");
    connect(logoutBtn, &QPushButton::clicked, this, &MainWindow::logout);
    head->addWidget(logoutBtn);
    root->addLayout(head);

    tabs_ = new QTabWidget;
    root->addWidget(tabs_, 1);

    // ================= Files tab =================
    auto* filesTab = new QWidget;
    auto* fl = new QVBoxLayout(filesTab);
    auto* nav = new QHBoxLayout;
    btnUp_ = new QPushButton(style()->standardIcon(QStyle::SP_ArrowUp), "Up");
    btnUp_->setToolTip("Go to the parent directory");
    connect(btnUp_, &QPushButton::clicked, this, &MainWindow::onUp);
    pathLabel_ = new QLabel("/");
    pathLabel_->setStyleSheet("font-family: monospace; font-weight: bold;");
    searchEdit_ = new QLineEdit;
    searchEdit_->setPlaceholderText("Search files by name...");
    searchEdit_->setClearButtonEnabled(true);
    searchEdit_->setMinimumWidth(240);
    searchEdit_->setMaximumWidth(380);
    auto* searchBtn = new QPushButton(style()->standardIcon(QStyle::SP_FileDialogContentsView), "Search");
    auto* clearBtn = new QPushButton("Clear");
    connect(searchBtn, &QPushButton::clicked, this, &MainWindow::onSearch);
    connect(searchEdit_, &QLineEdit::returnPressed, this, &MainWindow::onSearch);
    connect(clearBtn, &QPushButton::clicked, this, &MainWindow::onClearSearch);
    nav->addWidget(btnUp_);
    nav->addWidget(pathLabel_, 1);
    nav->addWidget(searchEdit_);
    nav->addWidget(searchBtn);
    nav->addWidget(clearBtn);
    buttons_ << btnUp_ << searchBtn << clearBtn;
    searchBtn->setObjectName("Search"); clearBtn->setObjectName("Clear");
    fl->addLayout(nav);

    fileTable_ = new QTableWidget(0, 6);
    fileTable_->setHorizontalHeaderLabels({"Name", "Type", "Size", "Owner", "Shared", "Modified"});
    fileTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    fileTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    fileTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    fileTable_->setAlternatingRowColors(true);
    fileTable_->verticalHeader()->setVisible(false);
    fileTable_->horizontalHeader()->setStretchLastSection(true);
    fileTable_->setColumnWidth(0, 340);
    connect(fileTable_, &QTableWidget::itemSelectionChanged, this, &MainWindow::onSelectionChanged);
    connect(fileTable_, &QTableWidget::cellDoubleClicked, this, [this](int, int) { onItemActivated(); });
    fl->addWidget(fileTable_, 1);

    auto* bar = new QHBoxLayout;
    // Every button below is wired to a real action. Buttons whose permission the role lacks are hidden.
    if (PermissionService::has(p, Perm::UPLOAD))
        addButton(bar, "Upload", "Upload a local file into the current directory", QStyle::SP_ArrowUp, &MainWindow::onUpload);
    if (PermissionService::has(p, Perm::DOWNLOAD))
        btnDownload_ = addButton(bar, "Download", "Download the selected file (SHA-256 verified)", QStyle::SP_ArrowDown, &MainWindow::onDownload);
    if (PermissionService::has(p, Perm::INFO))
        btnInfo_ = addButton(bar, "File Info", "Show details and SHA-256 of the selection", QStyle::SP_MessageBoxInformation, &MainWindow::onInfo);
    if (PermissionService::has(p, Perm::RENAME_OWN))
        btnRename_ = addButton(bar, "Rename", "Rename the selected file or directory", QStyle::SP_FileDialogDetailedView, &MainWindow::onRename);
    if (PermissionService::has(p, Perm::DELETE_OWN))
        btnDelete_ = addButton(bar, "Delete", "Delete the selected file", QStyle::SP_TrashIcon, &MainWindow::onDelete);
    if (PermissionService::has(p, Perm::SHARE_OWN))
        btnShare_ = addButton(bar, "Share / Unshare", "Toggle whether everyone can read the selected file", QStyle::SP_DriveNetIcon, &MainWindow::onShare);
    bar->addSpacing(16);
    if (PermissionService::has(p, Perm::MKDIR))
        addButton(bar, "New Folder", "Create a directory here", QStyle::SP_FileDialogNewFolder, &MainWindow::onNewFolder);
    if (PermissionService::has(p, Perm::RMDIR_OWN))
        btnRmdir_ = addButton(bar, "Remove Folder", "Remove the selected empty directory", QStyle::SP_DirIcon, &MainWindow::onRemoveFolder);
    bar->addStretch();
    auto* refreshBtn = new QPushButton(style()->standardIcon(QStyle::SP_BrowserReload), "Refresh");
    connect(refreshBtn, &QPushButton::clicked, this, [this]() { refresh(); });
    refreshBtn->setObjectName("Refresh");
    buttons_ << refreshBtn;
    bar->addWidget(refreshBtn);
    fl->addLayout(bar);
    tabs_->addTab(filesTab, "Files");

    // ================= History tab =================
    auto* histTab = new QWidget;
    auto* hl = new QVBoxLayout(histTab);
    historyTable_ = new QTableWidget(0, 7);
    historyTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    historyTable_->setAlternatingRowColors(true);
    historyTable_->verticalHeader()->setVisible(false);
    historyTable_->horizontalHeader()->setStretchLastSection(true);
    hl->addWidget(new QLabel(PermissionService::has(p, Perm::VIEW_ALL_HISTORY) ? "Transfers of all users:" : "Your transfers:"));
    hl->addWidget(historyTable_, 1);
    auto* hbtn = new QPushButton(style()->standardIcon(QStyle::SP_BrowserReload), "Refresh");
    hbtn->setObjectName("Refresh History");
    connect(hbtn, &QPushButton::clicked, this, [this]() { refreshHistory(); });
    buttons_ << hbtn;
    hl->addWidget(hbtn, 0, Qt::AlignLeft);
    tabs_->addTab(histTab, "Transfer History");

    // ================= System tab (faculty/admin) =================
    systemTable_ = new QTableWidget(0, 2);
    sysTimer_ = new QTimer(this);
    sysTimer_->setInterval(5000);
    connect(sysTimer_, &QTimer::timeout, this, [this]() { if (tabs_->tabText(tabs_->currentIndex()) == "System Monitor") refreshSystem(); });
    if (PermissionService::has(p, Perm::VIEW_SYSTEM)) {
        auto* tab = new QWidget;
        auto* l = new QVBoxLayout(tab);
        systemTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        systemTable_->setAlternatingRowColors(true);
        systemTable_->verticalHeader()->setVisible(false);
        systemTable_->horizontalHeader()->setStretchLastSection(true);
        systemTable_->setColumnWidth(0, 260);
        l->addWidget(new QLabel("Live server and Linux host statistics (procfs, sysfs, statvfs). Refreshes every 5 s:"));
        l->addWidget(systemTable_, 1);
        auto* b = new QPushButton(style()->standardIcon(QStyle::SP_BrowserReload), "Refresh");
        b->setObjectName("Refresh System");
        connect(b, &QPushButton::clicked, this, [this]() { refreshSystem(); });
        buttons_ << b;
        l->addWidget(b, 0, Qt::AlignLeft);
        tabs_->addTab(tab, "System Monitor");
        sysTimer_->start();
    }

    // ================= Users + Audit tabs (admin) =================
    usersTable_ = new QTableWidget(0, 5);
    auditTable_ = new QTableWidget(0, 6);
    if (PermissionService::has(p, Perm::MANAGE_USERS)) {
        auto* tab = new QWidget;
        auto* l = new QVBoxLayout(tab);
        usersTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        usersTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        usersTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        usersTable_->setAlternatingRowColors(true);
        usersTable_->verticalHeader()->setVisible(false);
        usersTable_->horizontalHeader()->setStretchLastSection(true);
        connect(usersTable_, &QTableWidget::itemSelectionChanged, this, &MainWindow::onSelectionChanged);
        l->addWidget(usersTable_, 1);
        auto* row = new QHBoxLayout;
        btnRoleSet_ = addButton(row, "Change Role", "Set the selected user's role", QStyle::SP_FileDialogContentsView, &MainWindow::onUserRole);
        btnUserDel_ = addButton(row, "Delete User", "Delete the selected user (their files are reassigned to you)", QStyle::SP_TrashIcon, &MainWindow::onUserDelete);
        auto* r = new QPushButton(style()->standardIcon(QStyle::SP_BrowserReload), "Refresh");
        r->setObjectName("Refresh Users");
        connect(r, &QPushButton::clicked, this, [this]() { refreshUsers(); });
        buttons_ << r;
        row->addStretch();
        row->addWidget(r);
        l->addLayout(row);
        tabs_->addTab(tab, "Users");
    }
    if (PermissionService::has(p, Perm::VIEW_AUDIT)) {
        auto* tab = new QWidget;
        auto* l = new QVBoxLayout(tab);
        auditTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        auditTable_->setAlternatingRowColors(true);
        auditTable_->verticalHeader()->setVisible(false);
        auditTable_->horizontalHeader()->setStretchLastSection(true);
        l->addWidget(auditTable_, 1);
        auto* r = new QPushButton(style()->standardIcon(QStyle::SP_BrowserReload), "Refresh");
        r->setObjectName("Refresh Audit");
        connect(r, &QPushButton::clicked, this, [this]() { refreshAudit(); });
        buttons_ << r;
        l->addWidget(r, 0, Qt::AlignLeft);
        tabs_->addTab(tab, "Audit Log");
    }
    connect(tabs_, &QTabWidget::currentChanged, this, &MainWindow::onTabChanged);

    statusBar()->showMessage("Ready");
    setStyleSheet("QPushButton { padding: 5px 12px; } QTableWidget { gridline-color: #ddd; }");
    onSelectionChanged();
    refresh();
}

QPushButton* MainWindow::button(const QString& text) const {
    for (QPushButton* b : buttons_) if (b->text() == text || b->objectName() == text) return b;
    return nullptr;
}

Principal MainWindow::me() const { return Principal{client_.userId(), client_.username(), client_.role()}; }

QPushButton* MainWindow::addButton(QLayout* lay, const QString& text, const QString& tip, int stdIcon, void (MainWindow::*slot)()) {
    auto* b = new QPushButton(style()->standardIcon(QStyle::StandardPixmap(stdIcon)), text);
    b->setToolTip(tip);
    connect(b, &QPushButton::clicked, this, slot);
    lay->addWidget(b);
    buttons_ << b;
    return b;
}

bool MainWindow::report(const Result& r, const QString& okMsg) {
    lastMessage_ = r.ok ? (okMsg.isEmpty() ? q(r.message) : okMsg) : q(r.message);
    statusBar()->showMessage(r.ok ? lastMessage_ : "Error: " + lastMessage_, r.ok ? 5000 : 10000);
    if (!r.ok) {
        if (r.status == Status::NETWORK || r.status == Status::AUTH_REQUIRED) {
            if (interactive_) QMessageBox::critical(this, "Session ended", lastMessage_ + "\nPlease sign in again.");
            logout();
        } else if (interactive_) {
            QMessageBox::warning(this, "Operation failed", lastMessage_);
        }
    }
    return r.ok;
}

QString MainWindow::pathFor(const QString& name) const {
    return currentPath_ == "/" ? "/" + name : currentPath_ + "/" + name;
}

void MainWindow::fillTable(QTableWidget* t, const QStringList& headers, const std::vector<QStringList>& rows) {
    t->clear();
    t->setColumnCount(headers.size());
    t->setHorizontalHeaderLabels(headers);
    t->setRowCount(int(rows.size()));
    for (int r = 0; r < int(rows.size()); ++r)
        for (int c = 0; c < headers.size(); ++c) t->setItem(r, c, new QTableWidgetItem(rows[size_t(r)].value(c)));
    t->resizeColumnsToContents();
    t->horizontalHeader()->setStretchLastSection(true);
}

void MainWindow::fillFiles(const std::vector<FileEntry>& v, bool showPath) {
    entries_ = v;
    fileTable_->clearContents();
    fileTable_->setRowCount(int(v.size()));
    for (int r = 0; r < int(v.size()); ++r) {
        const FileEntry& e = v[size_t(r)];
        QString name = showPath ? q(e.path) : q(e.name);
        if (e.isDir) name += "/";
        auto* it = new QTableWidgetItem(style()->standardIcon(e.isDir ? QStyle::SP_DirIcon : QStyle::SP_FileIcon), name);
        fileTable_->setItem(r, 0, it);
        fileTable_->setItem(r, 1, new QTableWidgetItem(e.isDir ? "Folder" : "File"));
        auto* sz = new QTableWidgetItem(e.isDir ? "-" : q(humanSize(e.size)));
        sz->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        fileTable_->setItem(r, 2, sz);
        fileTable_->setItem(r, 3, new QTableWidgetItem(q(e.owner)));
        fileTable_->setItem(r, 4, new QTableWidgetItem(e.isDir ? "-" : (e.shared ? "Yes" : "No")));
        fileTable_->setItem(r, 5, new QTableWidgetItem(q(formatTime(e.modified))));
    }
    onSelectionChanged();
}

// ---------------------------------------------------------------- actions
bool MainWindow::refresh() {
    if (!searchText_.isEmpty()) return searchFor(searchText_);
    std::vector<FileEntry> v;
    Result r = client_.list(currentPath_.toStdString(), v);
    if (!r.ok) return report(r);
    pathLabel_->setText(currentPath_);
    fillFiles(v, false);
    btnUp_->setEnabled(currentPath_ != "/");
    statusBar()->showMessage(QString("%1 item(s) in %2").arg(v.size()).arg(currentPath_), 4000);
    refreshHistory();
    return true;
}

bool MainWindow::openDir(const QString& path) {
    QString old = currentPath_;
    std::vector<FileEntry> v;
    Result r = client_.list(path.toStdString(), v);
    if (!r.ok) { currentPath_ = old; return report(r); }
    searchText_.clear();
    searchEdit_->clear();
    currentPath_ = path;
    pathLabel_->setText(path);
    fillFiles(v, false);
    btnUp_->setEnabled(currentPath_ != "/");
    return true;
}

bool MainWindow::uploadFile(const QString& localPath, bool shared, bool overwrite) {
    QFileInfo fi(localPath);
    QProgressDialog* pd = nullptr;
    if (interactive_) {
        pd = new QProgressDialog(QString("Uploading %1...").arg(fi.fileName()), "Cancel", 0, 100, this);
        pd->setWindowModality(Qt::WindowModal);
        pd->setMinimumDuration(300);
    }
    Client::Progress prog = nullptr;
    if (pd) prog = [pd](uint64_t d, uint64_t t) {
        pd->setValue(t ? int(d * 100 / t) : 100);
        QApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
        return !pd->wasCanceled();
    };
    Result r = client_.upload(localPath.toStdString(), currentPath_.toStdString(), fi.fileName().toStdString(), shared, overwrite, prog);
    if (pd) { pd->close(); delete pd; }
    if (!r.ok && r.status == Status::EXISTS && interactive_ && !overwrite) {
        if (QMessageBox::question(this, "File exists", QString("'%1' already exists here. Overwrite it?").arg(fi.fileName())) == QMessageBox::Yes)
            return uploadFile(localPath, shared, true);
        lastMessage_ = "upload cancelled";
        return false;
    }
    if (!report(r, QString("Uploaded %1 (SHA-256 verified by server)").arg(fi.fileName()))) return false;
    refresh();
    return true;
}

bool MainWindow::downloadTo(const QString& remotePath, const QString& localPath, bool overwrite) {
    QProgressDialog* pd = nullptr;
    if (interactive_) {
        pd = new QProgressDialog(QString("Downloading %1...").arg(remotePath), "Cancel", 0, 100, this);
        pd->setWindowModality(Qt::WindowModal);
        pd->setMinimumDuration(300);
    }
    Client::Progress prog = nullptr;
    if (pd) prog = [pd](uint64_t d, uint64_t t) {
        pd->setValue(t ? int(d * 100 / t) : 100);
        QApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
        return !pd->wasCanceled();
    };
    Result r = client_.download(remotePath.toStdString(), localPath.toStdString(), overwrite, prog);
    if (pd) { pd->close(); delete pd; }
    bool ok = report(r, QString("Downloaded to %1 - %2").arg(localPath, q(r.message)));
    if (ok) refreshHistory();
    return ok;
}

bool MainWindow::searchFor(const QString& text) {
    if (text.trimmed().isEmpty()) { searchText_.clear(); return refresh(); }
    std::vector<FileEntry> v;
    Result r = client_.search(text.trimmed().toStdString(), v);
    if (!r.ok) return report(r);
    searchText_ = text.trimmed();
    pathLabel_->setText(QString("Search results for \"%1\"").arg(searchText_));
    fillFiles(v, true);
    btnUp_->setEnabled(false);
    statusBar()->showMessage(QString("%1 match(es)").arg(v.size()), 5000);
    lastMessage_ = QString("%1 match(es)").arg(v.size());
    return true;
}

QString MainWindow::infoText(const QString& path) {
    FileEntry e;
    Result r = client_.info(path.toStdString(), e);
    if (!r.ok) { report(r); return QString(); }
    QString t = QString("Path: %1\nType: %2\nOwner: %3\n").arg(q(e.path), e.isDir ? "Directory" : "File", q(e.owner));
    if (!e.isDir)
        t += QString("Size: %1 bytes (%2)\nSHA-256: %3\nShared with everyone: %4\n")
                 .arg(e.size).arg(q(humanSize(e.size)), q(e.sha256), e.shared ? "yes" : "no");
    t += QString("Created: %1\nModified: %2").arg(q(formatTime(e.created)), q(formatTime(e.modified)));
    lastMessage_ = t;
    return t;
}

bool MainWindow::renameEntry(const QString& path, const QString& newName) {
    Result r = client_.rename(path.toStdString(), newName.toStdString());
    if (!report(r, "Renamed to " + newName)) return false;
    refresh();
    return true;
}
bool MainWindow::deleteFile(const QString& path) {
    if (!report(client_.removeFile(path.toStdString()), "File deleted")) return false;
    refresh();
    return true;
}
bool MainWindow::makeFolder(const QString& name) {
    if (!report(client_.makeDir(pathFor(name).toStdString()), "Folder created")) return false;
    refresh();
    return true;
}
bool MainWindow::removeFolder(const QString& path) {
    if (!report(client_.removeDir(path.toStdString()), "Folder removed")) return false;
    refresh();
    return true;
}
bool MainWindow::toggleShare(const QString& path) {
    FileEntry e;
    Result r = client_.info(path.toStdString(), e);
    if (!r.ok) return report(r);
    if (!report(client_.setShared(path.toStdString(), !e.shared))) return false;
    refresh();
    return true;
}

bool MainWindow::refreshHistory() {
    std::vector<TransferEntry> v;
    Result r = client_.history(200, v);
    if (!r.ok) return report(r);
    std::vector<QStringList> rows;
    for (auto& e : v)
        rows.push_back({q(formatTime(e.started)), q(e.username), q(e.direction), q(e.path), q(humanSize(e.size)), q(e.status), q(e.sha256.substr(0, 16))});
    fillTable(historyTable_, {"Started", "User", "Direction", "Path", "Size", "Status", "SHA-256 (prefix)"}, rows);
    historyTable_->setColumnWidth(3, 280);
    return true;
}

bool MainWindow::refreshUsers() {
    if (!PermissionService::has(me(), Perm::MANAGE_USERS)) return false;
    std::vector<UserEntry> v;
    Result r = client_.listUsers(v);
    if (!r.ok) return report(r);
    std::vector<QStringList> rows;
    for (auto& e : v) rows.push_back({QString::number(e.id), q(e.username), q(e.role), q(formatTime(e.created)), q(formatTime(e.lastLogin))});
    fillTable(usersTable_, {"ID", "Username", "Role", "Created", "Last login"}, rows);
    onSelectionChanged();
    return true;
}

bool MainWindow::refreshAudit() {
    if (!PermissionService::has(me(), Perm::VIEW_AUDIT)) return false;
    std::vector<AuditEntry> v;
    Result r = client_.audit(300, v);
    if (!r.ok) return report(r);
    std::vector<QStringList> rows;
    for (auto& e : v) rows.push_back({q(formatTime(e.ts)), q(e.username), q(e.action), q(e.result), q(e.target), q(e.detail)});
    fillTable(auditTable_, {"Time", "User", "Action", "Result", "Target", "Detail"}, rows);
    auditTable_->setColumnWidth(4, 240);
    return true;
}

bool MainWindow::refreshSystem() {
    if (!PermissionService::has(me(), Perm::VIEW_SYSTEM)) return false;
    KeyValues kv;
    Result r = client_.sysinfo(kv);
    if (!r.ok) return report(r);
    std::vector<QStringList> rows;
    for (auto& p : kv) rows.push_back({q(p.first), q(p.second)});
    fillTable(systemTable_, {"Metric", "Value"}, rows);
    systemTable_->setColumnWidth(0, 260);
    return true;
}

bool MainWindow::changeUserRole(const QString& user, const QString& role) {
    if (!report(client_.setUserRole(user.toStdString(), role.toStdString()), QString("%1 is now %2").arg(user, role))) return false;
    refreshUsers();
    return true;
}
bool MainWindow::removeUser(const QString& user) {
    if (!report(client_.deleteUser(user.toStdString()), "User deleted")) return false;
    refreshUsers();
    refresh();
    return true;
}

void MainWindow::logout() {
    if (loggedOut_) return;
    loggedOut_ = true;
    sysTimer_->stop();
    if (client_.loggedIn()) client_.logout();
    client_.disconnect();
    emit loggedOutSignal();
}

void MainWindow::closeEvent(QCloseEvent* e) {
    closedByUser_ = true;
    if (!loggedOut_) { loggedOut_ = true; sysTimer_->stop(); if (client_.loggedIn()) client_.logout(); client_.disconnect(); }
    e->accept();
}

// ---------------------------------------------------------------- selection helpers
void MainWindow::selectRow(int row) { fileTable_->selectRow(row); }

const FileEntry* MainWindow::selectedEntry() const {
    auto sel = fileTable_->selectionModel()->selectedRows();
    if (sel.isEmpty()) return nullptr;
    int r = sel.first().row();
    return (r >= 0 && size_t(r) < entries_.size()) ? &entries_[size_t(r)] : nullptr;
}

QString MainWindow::selectedUser() const {
    auto sel = usersTable_->selectionModel()->selectedRows();
    if (sel.isEmpty()) return QString();
    return usersTable_->item(sel.first().row(), 1)->text();
}

void MainWindow::onSelectionChanged() {
    const FileEntry* e = selectedEntry();
    Principal p = me();
    auto set = [](QPushButton* b, bool on) { if (b) b->setEnabled(on); };
    set(btnDownload_, e && !e->isDir);
    set(btnInfo_, e != nullptr);
    set(btnRename_, e && PermissionService::canRename(p, e->ownerId));
    set(btnDelete_, e && !e->isDir && PermissionService::canDeleteFile(p, e->ownerId));
    set(btnShare_, e && !e->isDir && PermissionService::canShare(p, e->ownerId));
    set(btnRmdir_, e && e->isDir && PermissionService::canRemoveDir(p, e->ownerId));
    bool u = !selectedUser().isEmpty();
    set(btnRoleSet_, u);
    set(btnUserDel_, u && selectedUser() != q(client_.username()));
}

void MainWindow::onTabChanged(int) {
    QString t = tabs_->tabText(tabs_->currentIndex());
    if (t == "Transfer History") refreshHistory();
    else if (t == "Users") refreshUsers();
    else if (t == "Audit Log") refreshAudit();
    else if (t == "System Monitor") refreshSystem();
}

// ---------------------------------------------------------------- slots collecting user input
void MainWindow::onUpload() {
    QString f = QFileDialog::getOpenFileName(this, "Select a file to upload");
    if (f.isEmpty()) return;
    auto choice = QMessageBox::question(this, "Share file?", "Make this file readable by all users (shared)?\nChoose No to keep it private.",
                                        QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel, QMessageBox::No);
    if (choice == QMessageBox::Cancel) return;
    uploadFile(f, choice == QMessageBox::Yes, false);
}

void MainWindow::onDownload() {
    const FileEntry* e = selectedEntry();
    if (!e || e->isDir) return;
    QString dest = QFileDialog::getSaveFileName(this, "Save as", q(e->name));
    if (dest.isEmpty()) return;
    downloadTo(q(e->path), dest, true);  // the save dialog already asked about overwriting
}

void MainWindow::onInfo() {
    const FileEntry* e = selectedEntry();
    if (!e) return;
    QString t = infoText(q(e->path));
    if (!t.isEmpty()) QMessageBox::information(this, "File information", t);
}

void MainWindow::onRename() {
    const FileEntry* e = selectedEntry();
    if (!e) return;
    bool ok = false;
    QString n = QInputDialog::getText(this, "Rename", "New name:", QLineEdit::Normal, q(e->name), &ok);
    if (ok && !n.trimmed().isEmpty()) renameEntry(q(e->path), n.trimmed());
}

void MainWindow::onDelete() {
    const FileEntry* e = selectedEntry();
    if (!e || e->isDir) return;
    if (QMessageBox::question(this, "Delete file", QString("Permanently delete '%1'?").arg(q(e->name))) == QMessageBox::Yes)
        deleteFile(q(e->path));
}

void MainWindow::onNewFolder() {
    bool ok = false;
    QString n = QInputDialog::getText(this, "New folder", "Folder name:", QLineEdit::Normal, "", &ok);
    if (ok && !n.trimmed().isEmpty()) makeFolder(n.trimmed());
}

void MainWindow::onRemoveFolder() {
    const FileEntry* e = selectedEntry();
    if (!e || !e->isDir) return;
    if (QMessageBox::question(this, "Remove folder", QString("Remove the empty folder '%1'?").arg(q(e->name))) == QMessageBox::Yes)
        removeFolder(q(e->path));
}

void MainWindow::onShare() {
    const FileEntry* e = selectedEntry();
    if (e && !e->isDir) toggleShare(q(e->path));
}

void MainWindow::onSearch() { searchFor(searchEdit_->text()); }
void MainWindow::onClearSearch() { searchEdit_->clear(); searchText_.clear(); refresh(); }

void MainWindow::onUp() {
    if (currentPath_ == "/") return;
    int i = currentPath_.lastIndexOf('/');
    openDir(i <= 0 ? "/" : currentPath_.left(i));
}

void MainWindow::onItemActivated() {
    const FileEntry* e = selectedEntry();
    if (!e) return;
    if (e->isDir) openDir(q(e->path));
    else onInfo();
}

void MainWindow::onUserRole() {
    QString u = selectedUser();
    if (u.isEmpty()) return;
    bool ok = false;
    QString role = QInputDialog::getItem(this, "Change role", QString("New role for %1:").arg(u), {"STUDENT", "FACULTY", "ADMIN"}, 0, false, &ok);
    if (ok) changeUserRole(u, role);
}

void MainWindow::onUserDelete() {
    QString u = selectedUser();
    if (u.isEmpty()) return;
    if (QMessageBox::question(this, "Delete user", QString("Delete user '%1'? Their files will be reassigned to you.").arg(u)) == QMessageBox::Yes)
        removeUser(u);
}
