#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcapsession.h"


namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(QWidget *parent = 0);
    ~MainWindow();

protected:
    void changeEvent(QEvent *e);

private:
    Ui::MainWindow *ui;
    QFuture<void> captureThread;


private slots:
    void on_clear_clicked();
    void on_capture_clicked();
    void on_stop_clicked();
    void on_available_ifaces_currentIndexChanged(QString );
    void on_about_clicked();
    void displayNewPacket(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
    void slotCaptureCompleted();
};






#endif // MAINWINDOW_H
