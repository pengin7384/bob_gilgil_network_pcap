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

    pcap_t* open();

    void run();
    void initItem(Item& item);
    void sendItem(Item item);
    void receiving(pcap_t* handle);

    Packet* getPacket(const u_char* packet, Item& item);
    IPv4* getIPv4(const u_char* packet, Item& item);
    TCP* getTCP(const u_char* packet, Item& item);
    UDP* getUDP(const u_char* packet, Item& item);
    ARP* getARP(const u_char* packet, Item& item);

    QString getType(u_int16_t &hType);
    QString getMacAddress(u_int8_t* hMacAddr);
    QString getIPv4Protocol(u_int8_t hProtocol);
    QString getARPProtocol(u_int16_t hProtocol);
    QString getAddress(u_int16_t hType, u_int8_t* hAddr);

public:
    void startCapture(QString target);
    QString getFirstInterface();
    QString getInterfaceList();

};




#endif // NETWORK_H
