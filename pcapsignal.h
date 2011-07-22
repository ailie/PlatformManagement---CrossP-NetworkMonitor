#ifndef PCAPSIGNAL_H
#define PCAPSIGNAL_H

#include <QObject>
#include <pcap.h>

class pcapSignal : public QObject
{
    Q_OBJECT

public:
    pcapSignal();
    void receivedPacket(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
    void captureCompleted();

signals:
    void signalReceivedPacket(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
    void signalCaptureCompleted();

};

#endif // PCAPSIGNAL_H
