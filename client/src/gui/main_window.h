#pragma once
#include <QMainWindow>
#include <vector>

#include "linsft/client.h"
#include "linsft/models.h"

class QAction;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTabWidget;
class QTimer;

// Main dashboard. Every button maps to a real client call; controls the current role may not use are hidden.
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(linsft::Client& client, const QString& serverLabel, QWidget* parent = nullptr);

    // ---- actions (called by the buttons after they collect input; also used by tests) ----
    bool refresh();
    bool openDir(const QString& path);
    bool uploadFile(const QString& localPath, bool shared = false, bool overwrite = false);
    bool downloadTo(const QString& remotePath, const QString& localPath, bool overwrite = true);
    bool searchFor(const QString& text);
    QString infoText(const QString& path);
    bool renameEntry(const QString& path, const QString& newName);
    bool deleteFile(const QString& path);
    bool makeFolder(const QString& name);
    bool removeFolder(const QString& path);
    bool toggleShare(const QString& path);
    bool refreshHistory();
    bool refreshUsers();
    bool refreshAudit();
    bool refreshSystem();
    bool changeUserRole(const QString& user, const QString& role);
    bool removeUser(const QString& user);
    void logout();

    void setInteractive(bool on) { interactive_ = on; }
    QString currentPath() const { return currentPath_; }
    QString lastMessage() const { return lastMessage_; }
    bool loggedOut() const { return loggedOut_; }
    bool closedByUser() const { return closedByUser_; }
    QTableWidget* fileTable() const { return fileTable_; }
    QTableWidget* historyTable() const { return historyTable_; }
    QTableWidget* usersTable() const { return usersTable_; }
    QTableWidget* auditTable() const { return auditTable_; }
    QTableWidget* systemTable() const { return systemTable_; }
    QTabWidget* tabs() const { return tabs_; }
    QList<QPushButton*> actionButtons() const { return buttons_; }
    QPushButton* button(const QString& text) const;
    void selectRow(int row);

signals:
    void loggedOutSignal();

protected:
    void closeEvent(QCloseEvent* e) override;

private slots:
    void onUpload();
    void onDownload();
    void onInfo();
    void onRename();
    void onDelete();
    void onNewFolder();
    void onRemoveFolder();
    void onShare();
    void onSearch();
    void onClearSearch();
    void onUp();
    void onItemActivated();
    void onSelectionChanged();
    void onUserRole();
    void onUserDelete();
    void onTabChanged(int idx);

private:
    QPushButton* addButton(class QLayout* lay, const QString& text, const QString& tip, int stdIcon, void (MainWindow::*slot)());
    bool report(const linsft::Result& r, const QString& okMsg = QString());
    void fillFiles(const std::vector<linsft::FileEntry>& v, bool showPath);
    const linsft::FileEntry* selectedEntry() const;
    QString selectedUser() const;
    void fillTable(QTableWidget* t, const QStringList& headers, const std::vector<QStringList>& rows);
    QString pathFor(const QString& name) const;
    linsft::Principal me() const;

    linsft::Client& client_;
    QString currentPath_ = "/";
    QString searchText_;
    QString lastMessage_;
    bool interactive_ = true, loggedOut_ = false, closedByUser_ = false;
    std::vector<linsft::FileEntry> entries_;

    QTabWidget* tabs_;
    QLabel *pathLabel_, *whoLabel_;
    QLineEdit* searchEdit_;
    QTableWidget *fileTable_, *historyTable_, *usersTable_, *auditTable_, *systemTable_;
    QList<QPushButton*> buttons_;
    QPushButton *btnDownload_ = nullptr, *btnInfo_ = nullptr, *btnRename_ = nullptr, *btnDelete_ = nullptr,
                *btnRmdir_ = nullptr, *btnShare_ = nullptr, *btnUp_ = nullptr, *btnRoleSet_ = nullptr, *btnUserDel_ = nullptr;
    QTimer* sysTimer_;
};
