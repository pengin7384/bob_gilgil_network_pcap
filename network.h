#ifndef NETWORK_H
#define NETWORK_H

#include <QThread>
#include <pcap/pcap.h>
#include <QStringList>
#include <QVariant>
#include <netinet/in.h>

#define HEADER_ETHER_SIZE 14
#define HEADER_IPv4_SIZE 20
#define HEADER_UDP_SIZE 8

#define TYPE_IPv4 0x0800
#define TYPE_ARP 0x0806

#define PROTOCOL_IPv4_TCP 0x06
#define PROTOCOL_IPv4_UDP 0x11
#define PROTOCOL_IPv4_ICMP 0x01
#define PROTOCOL_ARP 0x0800


class Network : public QThread {
    Q_OBJECT
signals:
    void signalGUI(QVariant data);

private:
    int index = 1;
    QString targetInterface;

    struct Packet {
        u_int8_t destAddr[6];
        u_int8_t srcAddr[6];
        u_int16_t type;
    };

    struct IPv4 {
        u_int8_t versionLength;
        u_int8_t serviceField;
        u_int16_t totalLength;
        u_int16_t identification;
        u_int16_t flags;
        u_int8_t ttl;
        u_int8_t protocol;
        u_int16_t checkSum;
        u_int8_t srcIP[4];
        u_int8_t destIP[4];
    };

    struct ARP {
        u_int16_t hardwareType;
        u_int16_t protocolType;
        u_int8_t hardwareSize;
        u_int8_t protocolSize;
        u_int16_t opcode;
        u_int8_t senderMacAddr[6];
        u_int8_t senderIPAddr[4];
        u_int8_t targetMacAddr[6];
        u_int8_t targetIPAddr[4];
    };

    struct TCP {
        u_int16_t srcPort;
        u_int16_t destPort;
        u_int32_t seqNum;
        u_int32_t ackNum;
        /*
        u_int8_t headerLength : 4;
        u_int16_t flag : 12;*/
        u_int8_t headerLength;
        u_int8_t flag;
        u_int16_t windowSize;
        u_int16_t checksum;
        u_int16_t urgent;
        u_int8_t* option;
    }; // __attribute__((packed))

    struct UDP {
        u_int16_t srcPort;
        u_int16_t destPort;
        u_int16_t length;
        u_int16_t checksum;
    };

    struct Item {
        u_int len; // Packet Length

        QString sNumber;
        QString sType;
        QString sSrcMacAddr;
        QString sDestMacAddr;
        QString sProtocol;
        QString sSrcAddr;
        QString sDestAddr;
        QString sLen;
        QString sSrcPort;
        QString sDestPort;
        QString sData;
    };

    void run() {
        pcap_t* handle = open();
        receiving(handle);
    }

    pcap_t* open() {
        char errBuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(targetInterface.toUtf8(), BUFSIZ, 1, 1000, errBuf);

        return handle;
    }

    void initItem(Item& item) {
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

    QString getType(u_int16_t &hType) {
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

    Packet* getPacket(const u_char* packet, Item& item) {
        Packet* pPacket = reinterpret_cast<Packet*>(const_cast<u_char*>(packet));

        u_int16_t hType = ntohs(pPacket->type);
        item.sType = getType(hType);
        item.sDestMacAddr = getMacAddress(pPacket->destAddr);
        item.sSrcMacAddr = getMacAddress(pPacket->srcAddr);
        return pPacket;
    }

    IPv4* getIPv4(const u_char* packet, Item& item) {
        IPv4* pIp = reinterpret_cast<IPv4*>(const_cast<u_char*>(packet+HEADER_ETHER_SIZE));

        item.sProtocol = getIPv4Protocol(pIp->protocol);
        item.sSrcAddr = getAddress(TYPE_IPv4, pIp->srcIP);
        item.sDestAddr = getAddress(TYPE_IPv4, pIp->destIP);
        item.sLen = QString(QString::number(ntohs(pIp->totalLength)+HEADER_ETHER_SIZE));
        return pIp;
    }

    TCP* getTCP(const u_char* packet, Item& item) {
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

    UDP* getUDP(const u_char* packet, Item& item) {
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

    ARP* getARP(const u_char* packet, Item& item) {
        ARP* pArp = reinterpret_cast<ARP*>(const_cast<u_char*>(packet+HEADER_ETHER_SIZE));

        u_int16_t hProtocol = ntohs(pArp->protocolType);
        item.sProtocol = getARPProtocol(hProtocol);
        item.sSrcAddr = getAddress(TYPE_ARP, pArp->senderIPAddr);
        item.sDestAddr = getAddress(TYPE_ARP, pArp->targetIPAddr);
        return pArp;
    }

    QString getMacAddress(u_int8_t* hMacAddr) {
        QString str = QString("%1:%2:%3:%4:%5:%6")
                .arg(QString::number(hMacAddr[0], 16))
                .arg(QString::number(hMacAddr[1], 16))
                .arg(QString::number(hMacAddr[2], 16))
                .arg(QString::number(hMacAddr[3], 16))
                .arg(QString::number(hMacAddr[4], 16))
                .arg(QString::number(hMacAddr[5], 16));
        return str;
    }

    QString getIPv4Protocol(u_int8_t hProtocol) {
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

    QString getARPProtocol(u_int16_t hProtocol) {
        QString sProtocol;
        if(hProtocol == PROTOCOL_ARP) {
            sProtocol = QString("IPv4");
        } else {
            sProtocol = QString("Unknown");
        }
        return sProtocol;
    }

    QString getAddress(u_int16_t hType, u_int8_t* hAddr) {
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

    void sendItem(Item item) {
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

    void receiving(pcap_t* handle) {

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

public:

    QString getFirstInterface() {
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

    QString getInterfaceList() {
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

    void startCapture(QString target) {
        targetInterface = target;
        start();
    }

};




#endif // NETWORK_H
