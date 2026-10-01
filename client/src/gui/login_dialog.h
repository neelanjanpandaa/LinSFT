#pragma once
#include <QDialog>

#include "linsft/client.h"

class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;

// Sign-in / registration dialog. Connects to the server and authenticates through linsft::Client.
class LoginDialog : public QDialog {
    Q_OBJECT
public:
    LoginDialog(linsft::Client& client, const QString& host, int port, QWidget* parent = nullptr);
    QString host() const;
    int port() const;

    // Programmatic entry points (used by the buttons and by the GUI tests)
    bool doLogin(const QString& user, const QString& password);
    bool doRegister(const QString& user, const QString& password, const QString& confirm);
    void setInteractive(bool on) { interactive_ = on; }
    QString lastMessage() const { return lastMessage_; }

private slots:
    void onLoginClicked();
    void onRegisterClicked();

private:
    bool ensureConnected();
    void showError(const QString& text);
    void showInfo(const QString& text);

    linsft::Client& client_;
    QLineEdit *hostEdit_, *userEdit_, *passEdit_;
    QSpinBox* portSpin_;
    QPushButton *loginBtn_, *registerBtn_, *quitBtn_;
    QLabel* status_;
    bool interactive_ = true;
    QString lastMessage_;
};
