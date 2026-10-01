#include "login_dialog.h"

#include <QFormLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

using namespace linsft;

LoginDialog::LoginDialog(Client& client, const QString& host, int port, QWidget* parent)
    : QDialog(parent), client_(client) {
    setWindowTitle("LinSFT - Sign in");
    setModal(true);
    auto* title = new QLabel("<h2>LinSFT</h2><span style='color:gray'>Linux Secure File Transfer</span>");
    title->setAlignment(Qt::AlignCenter);
    hostEdit_ = new QLineEdit(host);
    portSpin_ = new QSpinBox;
    portSpin_->setRange(1, 65535);
    portSpin_->setValue(port);
    userEdit_ = new QLineEdit;
    userEdit_->setPlaceholderText("username");
    passEdit_ = new QLineEdit;
    passEdit_->setEchoMode(QLineEdit::Password);
    passEdit_->setPlaceholderText("password");
    auto* form = new QFormLayout;
    form->addRow("Server:", hostEdit_);
    form->addRow("Port:", portSpin_);
    form->addRow("Username:", userEdit_);
    form->addRow("Password:", passEdit_);
    status_ = new QLabel;
    status_->setWordWrap(true);
    status_->setStyleSheet("color:#b00020");
    loginBtn_ = new QPushButton("Login");
    loginBtn_->setDefault(true);
    registerBtn_ = new QPushButton("Register");
    quitBtn_ = new QPushButton("Quit");
    auto* row = new QHBoxLayout;
    row->addWidget(registerBtn_);
    row->addStretch();
    row->addWidget(quitBtn_);
    row->addWidget(loginBtn_);
    auto* lay = new QVBoxLayout(this);
    lay->addWidget(title);
    lay->addLayout(form);
    lay->addWidget(status_);
    lay->addLayout(row);
    setMinimumWidth(380);
    connect(loginBtn_, &QPushButton::clicked, this, &LoginDialog::onLoginClicked);
    connect(registerBtn_, &QPushButton::clicked, this, &LoginDialog::onRegisterClicked);
    connect(quitBtn_, &QPushButton::clicked, this, &QDialog::reject);
    connect(passEdit_, &QLineEdit::returnPressed, this, &LoginDialog::onLoginClicked);
    userEdit_->setFocus();
}

QString LoginDialog::host() const { return hostEdit_->text().trimmed(); }
int LoginDialog::port() const { return portSpin_->value(); }

void LoginDialog::showError(const QString& t) { lastMessage_ = t; status_->setStyleSheet("color:#b00020"); status_->setText(t); }
void LoginDialog::showInfo(const QString& t) { lastMessage_ = t; status_->setStyleSheet("color:#2e7d32"); status_->setText(t); }

bool LoginDialog::ensureConnected() {
    if (client_.connected()) return true;
    Result r = client_.connectTo(host().toStdString(), uint16_t(port()), 30);
    if (!r.ok) {
        showError(QString::fromStdString(r.message) + "\nIs network-file-server running?");
        return false;
    }
    return true;
}

bool LoginDialog::doLogin(const QString& user, const QString& pass) {
    if (user.trimmed().isEmpty() || pass.isEmpty()) { showError("Enter username and password."); return false; }
    if (!ensureConnected()) return false;
    Result r = client_.login(user.trimmed().toStdString(), pass.toStdString());
    if (!r.ok) {
        showError(QString::fromStdString(r.message));
        if (!client_.connected()) showError(QString::fromStdString(r.message) + " (connection lost - try again)");
        return false;
    }
    showInfo("Signed in.");
    accept();
    return true;
}

bool LoginDialog::doRegister(const QString& user, const QString& pass, const QString& confirm) {
    if (pass != confirm) { showError("Passwords do not match."); return false; }
    if (!ensureConnected()) return false;
    Result r = client_.registerUser(user.trimmed().toStdString(), pass.toStdString());
    if (!r.ok) { showError(QString::fromStdString(r.message)); return false; }
    showInfo("Account created. Signing in...");
    return doLogin(user, pass);
}

void LoginDialog::onLoginClicked() { doLogin(userEdit_->text(), passEdit_->text()); }

void LoginDialog::onRegisterClicked() {
    QString user = userEdit_->text().trimmed(), pass = passEdit_->text();
    if (user.isEmpty() || pass.isEmpty()) { showError("Enter the desired username and password above, then click Register."); return; }
    bool ok = true;
    QString confirm = interactive_ ? QInputDialog::getText(this, "Register", "Repeat password:", QLineEdit::Password, "", &ok) : pass;
    if (!ok) return;
    doRegister(user, pass, confirm);
}
