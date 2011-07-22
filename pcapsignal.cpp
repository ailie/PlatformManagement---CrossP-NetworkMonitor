#include "pcapsignal.h"

pcapSignal::pcapSignal()
{
}

void pcapSignal::receivedPacket(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    emit signalReceivedPacket(param, header, pkt_data);
}

void pcapSignal::captureCompleted()
{
    emit signalCaptureCompleted();
}
