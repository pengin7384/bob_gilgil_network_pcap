#include "network.h"



// private

pcap_t* Network::open() {
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(targetInterface.toUtf8(), BUFSIZ, 1, 1000, errBuf);

    return handle;
}

void Network::run() {
    pcap_t* handle = open();
    receiving(handle);
}

void Network::initItem(Item& item) {
    item.len = 0;
    item.sNumber = QString("Unknown");
    item.sType = QString("Unknown");
    item.sSrcMacAddr = QString("Unknown");
    item.sDestMacAddr = QString("Unknown");
    item.sProtocol = QString("Unknown");
    item.sSrcAddr = QString("Unknown");
    item.sDestAddr = QString("Unknown");
    item.sLen = QString("Unknown");
    item.sSrcPort = QString("Unknown");
    item.sDestPort = QString("Unknown");
    item.sData = QString("Unknown");
}

void Network::sendItem(Item item) {
    item.sNumber = QString::number(index++);
    QStringList list = QStringList() << item.sNumber
                                     << item.sType
                                     << item.sSrcMacAddr
                                     << item.sDestMacAddr
                                     << item.sProtocol
                                     << item.sSrcAddr
                                     << item.sDestAddr
                                     << item.sLen
                                     << item.sSrcPort
                                     << item.sDestPort
                                     << item.sData;
    emit signalGUI(QVariant(list));
}

void Network::receiving(pcap_t* handle) {

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if(res >= -2 && res <= 0) {
            break;
        }

        Item item;
        initItem(item);
        item.len = header->len;

        Packet* pPacket = getPacket(packet, item);
        u_int16_t hType = ntohs(pPacket->type);

        if(hType == TYPE_IPv4) {
            IPv4* pIp = getIPv4(packet, item);

            if(pIp->protocol == PROTOCOL_IPv4_TCP) {
                TCP* pTcp = getTCP(packet, item);

            } else if(pIp->protocol == PROTOCOL_IPv4_UDP) {
                UDP* pUdp = getUDP(packet, item);

            }

            sendItem(item);

        } else if(hType == TYPE_ARP) {
            ARP* pArp = getARP(packet, item);

            sendItem(item);
        }
    }
    pcap_close(handle);
}

Network::Packet* Network::getPacket(const u_char* packet, Item& item) {
    Packet* pPacket = reinterpret_cast<Packet*>(const_cast<u_char*>(packet));

    u_int16_t hType = ntohs(pPacket->type);
    item.sType = getType(hType);
    item.sDestMacAddr = getMacAddress(pPacket->destAddr);
    item.sSrcMacAddr = getMacAddress(pPacket->srcAddr);
    return pPacket;
}

Network::IPv4* Network::getIPv4(const u_char* packet, Item& item) {
    IPv4* pIp = reinterpret_cast<IPv4*>(const_cast<u_char*>(packet+HEADER_ETHER_SIZE));

    item.sProtocol = getIPv4Protocol(pIp->protocol);
    item.sSrcAddr = getAddress(TYPE_IPv4, pIp->srcIP);
    item.sDestAddr = getAddress(TYPE_IPv4, pIp->destIP);
    item.sLen = QString(QString::number(ntohs(pIp->totalLength)+HEADER_ETHER_SIZE));
    return pIp;
}

Network::TCP* Network::getTCP(const u_char* packet, Item& item) {
    TCP* pTcp = reinterpret_cast<TCP*>(const_cast<u_char*>(packet+HEADER_ETHER_SIZE+HEADER_IPv4_SIZE));

    item.sSrcPort = QString(QString::number(ntohs(pTcp->srcPort)));
    item.sDestPort = QString(QString::number(ntohs(pTcp->destPort)));
    int tcpLength = pTcp->headerLength>>4<<2;
    u_int8_t* pData = reinterpret_cast<u_int8_t*>(const_cast<u_char*>(packet+HEADER_ETHER_SIZE+HEADER_IPv4_SIZE+tcpLength));
    QString temp = QString();
    int restSize = static_cast<int>(item.len)-(HEADER_ETHER_SIZE+HEADER_IPv4_SIZE+tcpLength);

    for(int i=0; (i<restSize)&&(i<10); i++) {
        QString str;
        str.sprintf("%02x ", pData[i]);
        temp = temp + str;
    }
    item.sData = QString(temp);
    return pTcp;
}

Network::UDP* Network::getUDP(const u_char* packet, Item& item) {
    UDP* pUdp = reinterpret_cast<UDP*>(const_cast<u_char*>(packet+HEADER_ETHER_SIZE+HEADER_IPv4_SIZE));

    item.sSrcPort = QString(QString::number(ntohs(pUdp->srcPort)));
    item.sDestPort = QString(QString::number(ntohs(pUdp->destPort)));
    u_int8_t* pData = reinterpret_cast<u_int8_t*>(const_cast<u_char*>(packet+HEADER_ETHER_SIZE+HEADER_IPv4_SIZE+HEADER_UDP_SIZE));

    QString temp = QString();
    for(int i=0; (i<(ntohs(pUdp->length)-8))&&(i<10); i++) {
        QString str;
        str.sprintf("%02x ", pData[i]);
        temp = temp + str;
    }
    item.sData = QString(temp);
    return pUdp;
}

Network::ARP* Network::getARP(const u_char* packet, Item& item) {
    ARP* pArp = reinterpret_cast<ARP*>(const_cast<u_char*>(packet+HEADER_ETHER_SIZE));

    u_int16_t hProtocol = ntohs(pArp->protocolType);
    item.sProtocol = getARPProtocol(hProtocol);
    item.sSrcAddr = getAddress(TYPE_ARP, pArp->senderIPAddr);
    item.sDestAddr = getAddress(TYPE_ARP, pArp->targetIPAddr);
    return pArp;
}


QString Network::getType(u_int16_t &hType) {
    QString sType;

    if(hType == TYPE_IPv4) {
        sType = QString("IPv4");
    } else if(hType == TYPE_ARP) {
        sType = QString("ARP");
    } else {
        sType = QString("Unknown "+QString::number(hType, 16));
    }
    return sType;
}

QString Network::getMacAddress(u_int8_t* hMacAddr) {
    QString str = QString("%1:%2:%3:%4:%5:%6")
            .arg(QString::number(hMacAddr[0], 16))
            .arg(QString::number(hMacAddr[1], 16))
            .arg(QString::number(hMacAddr[2], 16))
            .arg(QString::number(hMacAddr[3], 16))
            .arg(QString::number(hMacAddr[4], 16))
            .arg(QString::number(hMacAddr[5], 16));
    return str;
}

QString Network::getIPv4Protocol(u_int8_t hProtocol) {
    QString sProtocol;
    if(hProtocol == PROTOCOL_IPv4_TCP) {
        sProtocol = QString("TCP");
    } else if(hProtocol == PROTOCOL_IPv4_UDP) {
        sProtocol = QString("UDP");
    } else {
        sProtocol = QString("Unknown");
    }
    return sProtocol;
}

QString Network::getARPProtocol(u_int16_t hProtocol) {
    QString sProtocol;
    if(hProtocol == PROTOCOL_ARP) {
        sProtocol = QString("IPv4");
    } else {
        sProtocol = QString("Unknown");
    }
    return sProtocol;
}

QString Network::getAddress(u_int16_t hType, u_int8_t* hAddr) {
    QString sAddr;
    if(hType == TYPE_IPv4 || hType == TYPE_ARP) {
        QString str = QString("%1.%2.%3.%4")
                .arg(QString::number(hAddr[0], 10))
                .arg(QString::number(hAddr[1], 10))
                .arg(QString::number(hAddr[2], 10))
                .arg(QString::number(hAddr[3], 10));
        sAddr = QString(str);
    } else {
        sAddr = QString("Unknown");
    }

    return sAddr;
}






// public

void Network::startCapture(QString target) {
    targetInterface = target;
    start();
}

QString Network::getFirstInterface() {
    pcap_if_t *ifs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&ifs, errbuf)==-1 || ifs == nullptr) {
        return "";
    } else {
        pcap_if_t* pIf;
        pIf=ifs;
        return pIf->name;
    }
}

QString Network::getInterfaceList() {
    pcap_if_t *ifs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&ifs, errbuf)==-1 || ifs == nullptr) {
        return nullptr;
    }

    QString str = "";

    pcap_if_t* pIf;
    for(pIf=ifs; pIf!=nullptr; pIf=pIf->next) {
        str = str + pIf->name + "\n";
    }

    pcap_freealldevs(ifs);

    return str;
}

