// network-file-gui: Qt6 desktop client. Shows the login dialog, then the dashboard; logout returns to login.
#include <QApplication>
#include <QCommandLineParser>
#include <QStyleFactory>

#include "login_dialog.h"
#include "main_window.h"

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    app.setApplicationName("LinSFT");
    app.setStyle(QStyleFactory::create("Fusion"));
    QCommandLineParser parser;
    parser.setApplicationDescription("LinSFT desktop client");
    parser.addHelpOption();
    QCommandLineOption hostOpt({"H", "host"}, "Server host", "host", "127.0.0.1");
    QCommandLineOption portOpt({"p", "port"}, "Server port", "port", "5000");
    parser.addOption(hostOpt);
    parser.addOption(portOpt);
    parser.process(app);

    app.setQuitOnLastWindowClosed(false);
    for (;;) {
        linsft::Client client;
        LoginDialog login(client, parser.value(hostOpt), parser.value(portOpt).toInt());
        if (login.exec() != QDialog::Accepted) break;
        QString label = QString("%1:%2").arg(login.host()).arg(login.port());
        MainWindow win(client, label);
        QEventLoop loop;
        QObject::connect(&win, &MainWindow::loggedOutSignal, &loop, &QEventLoop::quit);
        QObject::connect(&app, &QApplication::lastWindowClosed, &loop, &QEventLoop::quit);
        win.show();
        loop.exec();
        if (win.closedByUser() || !win.loggedOut()) break;  // window X or Quit exits; Logout loops back to login
        win.hide();
    }
    return 0;
}
