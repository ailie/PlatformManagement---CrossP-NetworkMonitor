#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "dialogabout.h"

MainWindow::MainWindow(QWidget *parent) :
        QMainWindow(parent),
        ui(new Ui::MainWindow)
{

    ui->setupUi(this);


    pcapSession::getAvailableDevices();


    foreach (QString ifaceName, pcapSession::allDevs.keys())
        ui->available_ifaces->addItem(QIcon("icons/wired.png"), ifaceName);


    if( ui->available_ifaces->count() )
    {
        ui->available_ifaces->setEnabled(1);
        ui->capture->setEnabled(1);
    }


    connect(
            &(pcapSession::helper), SIGNAL(signalReceivedPacket(u_char*, const struct pcap_pkthdr*, const u_char*)),
            this                  , SLOT  (displayNewPacket    (u_char*, const struct pcap_pkthdr*, const u_char*))
            );


    connect(
            &(pcapSession::helper), SIGNAL(signalCaptureCompleted()),
            this                  , SLOT  (slotCaptureCompleted()  )
            );

}


MainWindow::~MainWindow()
{
    on_stop_clicked();
    captureThread.waitForFinished();

    delete ui;
    qWarning("MainWindow object destroyed");
}


void MainWindow::changeEvent(QEvent *e)
{
    QMainWindow::changeEvent(e);
    switch (e->type()) {
    case QEvent::LanguageChange:
        ui->retranslateUi(this);
        break;
    default:
        break;
    }
}

void MainWindow::on_about_clicked()
{
    DialogAbout d;
    d.exec();
}


void MainWindow::on_available_ifaces_currentIndexChanged(QString a)
{

    ui->grid1_label1->setText(pcapSession::allDevs.value(a).descrip);

    ui->grid1_label2->setText(pcapSession::allDevs.value(a).addr_qstr);
    ui->grid1_label3->setText(pcapSession::allDevs.value(a).bcast_qstr);
    ui->grid1_label4->setText(pcapSession::allDevs.value(a).mask_qstr);

}


void MainWindow::displayNewPacket(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

    /* retireve the position of the ip header */
    pcapSession::ip_header *ipHeader = (pcapSession::ip_header *) (pkt_data + 14); //skip the length of ethernet header

    // Warning !ihl stores the length of the IPv4 header, in 32 bit words, but we  need it in 8 bit words (octets)
    u_int ipHeaderLength = (ipHeader->ver_ihl & 0xf) * 4;
    u_short ipTotalLength = ntohs(ipHeader->tlen);


    if (ipHeaderLength < 20)
    {
        qWarning("Invalid IP header length: %u bytes", ipHeaderLength);
        return;
    }


    QString srcAddress = pcapSession::addrConverter(ipHeader->saddr);
    QString dstAddress = pcapSession::addrConverter(ipHeader->daddr);


    // DNS query for "picasaweb.google.com"
    // HTTP GET for "http://www.dsq.com/Images/AncientBackGround.GIF"


    if ( ipHeader->proto == 17 )
    {
        pcapSession::dns_header *dnsHeader = (pcapSession::dns_header *) (pkt_data + 14 + ipHeaderLength + 8);


        if( ntohs(dnsHeader->qdcount) == 1)
        {

            u_char *c = (u_char *) (dnsHeader + 1);


            int pos = 0;
            QString qname;


            while ( c[pos] )
            {

                for( int i=1 ; i<=c[pos] ; i++ )
                    qname.append( c[pos+i] );

                pos = pos + c[pos] + 1;

                if( c[pos] )
                    qname.append(".");
            }




            ui->list_01->addItem(qname);

            ui->grid2_label1->setNum( ui->list_01->count() );

            return;

        }

        qWarning("Ignored IPv4 packet carying protocol %d: %s -> %s with ipTotalLength of %d bytes",
                 ipHeader->proto,
                 srcAddress.toAscii().data(),
                 dstAddress.toAscii().data(),
                 ipTotalLength
                 );

        return;
    }


    if ( ipHeader->proto == 6 )
    {
        pcapSession::tcp_header *tcpHeader = (pcapSession::tcp_header *) (pkt_data + 14 + ipHeaderLength);

        // the length of TCP header is only stored in the first 4 bits of tcpHeader->x2_off
        u_int tcpHeaderLength = (tcpHeader->x2_off  >> 4) * 4;

        u_int httpLength = ipTotalLength - ipHeaderLength - tcpHeaderLength;


        if( httpLength )
        {


            QStringList httpData = QString( (char*) tcpHeader + tcpHeaderLength ).split("\r\n");
            QStringList requestLine = httpData.value(0).split(" ");
            QStringList hostHeaderField;


            int i = httpData.indexOf(  QRegExp("^Host: .*") );

            if( i >= 0)
            {
                hostHeaderField = httpData.value(i).split(" ");

                ui->list_02->addItem(
                        requestLine.value(0) + " " +
                        hostHeaderField.value(1) +
                        requestLine.value(1)
                        );

                ui->grid2_label2->setNum( ui->list_02->count() );

                return;
            }

            //            qWarning("\n\n--------------------------------------------------------------------------------------\n%s",
            //                    httpData.join("\r\n").toAscii().data()
            //                    );

        }

        qWarning("Ignored IPv4 packet carying protocol %d: %s -> %s with httpLength of %d bytes",
                 ipHeader->proto,
                 srcAddress.toAscii().data(),
                 dstAddress.toAscii().data(),
                 httpLength
                 );

        return;
    }


    qWarning("Ignored IPv4 packet carying protocol %d: %s -> %s with IPv4 header length of %d bytes",
             ipHeader->proto,
             srcAddress.toAscii().data(),
             dstAddress.toAscii().data(),
             ipHeaderLength
             );

}


void MainWindow::on_stop_clicked()
{
    pcapSession::stopCapture();
    ui->stop->setEnabled(0);
}

void MainWindow::slotCaptureCompleted()
{
    ui->available_ifaces->setEnabled(1);
    ui->capture->setEnabled(1);
}

void MainWindow::on_capture_clicked()
{
    ui->available_ifaces->setEnabled(0);
    ui->capture->setEnabled(0);
    ui->stop->setEnabled(1);

    captureThread = QtConcurrent::run(
            pcapSession::startCapture,
            ui->available_ifaces->currentText().toAscii()
            );
}

void MainWindow::on_clear_clicked()
{
    ui->list_01->clear();
    ui->list_02->clear();
    ui->grid2_label1->setNum(0);
    ui->grid2_label2->setNum(0);
}
