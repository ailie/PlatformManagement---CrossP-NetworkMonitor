#include "pcapsession.h"


pcapSignal pcapSession::helper;
pcap_t* pcapSession::adhandle=0;
QHash<QString, pcapSession::devInfo> pcapSession::allDevs;




void pcapSession::getAvailableDevices()
{
    allDevs.clear();

    pcap_if_t *allDevsP;

    char errbuf[PCAP_ERRBUF_SIZE+1];


    // Retrieve the network interfaces list
    if (pcap_findalldevs(&allDevsP, errbuf) == -1)
        qWarning("Error in pcap_findalldevs: %s\n", errbuf);





    for( pcap_if_t *currentDev=allDevsP ; currentDev ; currentDev=currentDev->next )
    {

        // struct used to store infos about one iface at a time
        devInfo currentDevData;

        u_int
                inet_addr   = 0,
                bcast       = 0,
                mask        = 0;


        for( pcap_addr_t *currentAddress=currentDev->addresses ; currentAddress ; currentAddress=currentAddress->next )
        {
            if(currentAddress->addr->sa_family == AF_INET)
            {

                if(currentAddress->addr)
                    inet_addr    = ((struct sockaddr_in *) currentAddress->addr)      ->sin_addr.s_addr;

                if(currentAddress->netmask)
                    mask         = ((struct sockaddr_in *) currentAddress->netmask)   ->sin_addr.s_addr;

                // this sets the correct broadcast adress on linux, but fails on Windows XP, returning bcast = 1
//                if(currentAddress->broadaddr)
//                    bcast        = ((struct sockaddr_in *) currentAddress->broadaddr) ->sin_addr.s_addr;

                // so, instead of taking a ready computed bcast adress, we obtain it ourselves from IP and subnet mask
                if( inet_addr && mask )
                    bcast = inet_addr | (~mask);

            }
        }


        currentDevData.addr_uint = inet_addr;
        currentDevData.addr_qstr = addrConverter( (ip_address &) inet_addr);

        currentDevData.bcast_uint = bcast;
        currentDevData.bcast_qstr = addrConverter( (ip_address &) bcast);

        currentDevData.mask_uint = mask;
        currentDevData.mask_qstr = addrConverter( (ip_address &) mask);


        // store the current iface description in our temp struct
        if(currentDev->description)
            currentDevData.descrip=currentDev->description;
        else
            currentDevData.descrip="No description available.";


        // append to the list of found interfaces the current one (name + descr)
        allDevs.insert(currentDev->name, currentDevData);

    }

    /* Free the device list */
    pcap_freealldevs(allDevsP);
}


//"src host 192.168.1.88 && (ip proto 6 || ip proto 17)"
void pcapSession::startCapture(const char* captureDevName)
{
    if( QString(captureDevName).isEmpty() )
        return;

    char errbuf[PCAP_ERRBUF_SIZE];


    // Initialize the handler for listening
    adhandle = pcap_open_live(captureDevName, 65535, 0, 2000, errbuf);


    struct bpf_program fcode;

    QString filter="src host " + allDevs.value(captureDevName).addr_qstr + " && ( tcp dst port 80 || udp dst port 53 )";


    //compile the filter
    if( pcap_compile(
            adhandle,
            &fcode,
            filter.toAscii(),
            1,
            allDevs.value(captureDevName).mask_uint
            ) < 0 )
        qWarning("Error compiling filter: wrong syntax");


    //set the filter
    if( pcap_setfilter(adhandle, &fcode) < 0 )
        qWarning("Error setting the filter");


    qWarning("pcap_loop: <%s> begins capturing packets", captureDevName);

    // Start the capture

    if ( pcap_loop(adhandle, 0, legacyCallback, NULL) == -1 )
        qWarning("Error in pcap_loop");


    qWarning("pcap_loop: <%s> stops capturing packets", captureDevName);

    helper.captureCompleted();
}


void pcapSession::stopCapture()
{
    if(adhandle)
        pcap_breakloop(adhandle);
}


void pcapSession::legacyCallback(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    helper.receivedPacket(param, header, pkt_data);
}


QString pcapSession::addrConverter(const ip_address &addr)
{
    if( (u_int&) addr == 0 )
        return "unassigned";

    return
            QString::number(addr.byte1) + "." +
            QString::number(addr.byte2) + "." +
            QString::number(addr.byte3) + "." +
            QString::number(addr.byte4);
}
