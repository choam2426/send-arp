#include "pch.h"
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <target IP>\n");
	printf("sample: send-arp-test wlan0 192.168.1.1\n");
}

void getMAC(char *iface, unsigned char *mac) {
        int fd;
        struct ifreq ifr;
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
        ioctl(fd, SIOCGIFHWADDR, &ifr);
        close(fd);
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

	int fd;
    struct ifreq ifr;
    char *iface = argv[1];
    unsigned char mac[6];
	getMAC(argv[1], mac);
	char macStr[18];
	sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';

    // get ip address
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("SIOCGIFADDR");
        return 1;
    }
    char* my_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

    // get mac address
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        return 1;
    }

    close(fd);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", iface, errbuf);
		return -1;
	}

	EthArpPacket arp_packet;

	arp_packet.eth_.dmac_ = Mac("00-00-00-00-00-00");
	arp_packet.eth_.smac_ = Mac(mac);
	arp_packet.eth_.type_ = htons(EthHdr::Arp);
	arp_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	arp_packet.arp_.pro_ = htons(EthHdr::Ip4);
	arp_packet.arp_.hln_ = Mac::SIZE;
	arp_packet.arp_.pln_ = Ip::SIZE;
	arp_packet.arp_.op_ = htons(ArpHdr::Reply);
	arp_packet.arp_.sip_ = htonl(Ip(my_ip));
	arp_packet.arp_.smac_ = Mac(mac);
	arp_packet.arp_.tmac_ = Mac("00-00-00-00-00-00");
	arp_packet.arp_.tip_ = htonl(Ip(argv[2]));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
