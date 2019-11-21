#pragma once

#pragma once
#include <pcap.h>
#include <stdio.h>
#include <tchar.h>
#include <WinSock2.h>
#include <Windows.h>

#include <map>

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"ws2_32.lib")

using namespace std;

//设置Npcap的DLL文件路径,并需配置DLL延迟加载
bool LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, " [X]Error in GetSystemDirectory: %x", GetLastError());
		return false;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, " [X]Error in SetDllDirectory: %x", GetLastError());
		return false;
	}
	cout << " [X]Npcap load success." << endl;
	return true;
}

//获取网卡列表
pcap_if_t* findAlldevs() {

	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		//exit(1);
		return NULL;
	}
	return alldevs;
}



/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS	12
char* iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char* p;

	p = (u_char*)& in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

//把输入的字符串格式mac转成十六进制数
BOOL mac_str_to_bin(char* str, char* mac)
{
	int i;
	char* s;
	char* e;
	if ((mac == NULL) || (str == NULL))
	{
		return FALSE;
	}
	s = (char*)str;
	e = (char*)mac;
	for (i = 0; i < 6; ++i)
	{
		mac[i] = s ? strtoul(s, &e, 16) : 0;
		if (s)
			s = (*e) ? e + 1 : e;
	}
	return TRUE;
}

//根据传入的pcap网卡信息结构输出网卡信息
bool ifPrint(pcap_if_t* d) {

	pcap_addr_t* a;
	//其实并不需要输出网卡名
	cout << d->name<<"\t";
	cout << d->description<<"\t";
	for (a = d->addresses; a; a = a->next) {

		switch (a->addr->sa_family)
		{
		//只关注ipv4
		case AF_INET:
			if (a->addr) {
				//printf("%s", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
				cout << iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr);
				continue;
			}
			break;
		default:
			break;
		}
	}
	cout <<"\t"<< endl;
	return true;

}

//列出所有网卡信息
bool listDevs(pcap_if_t* alldevs) {

	int num = 0;
	pcap_if_t* d;
	for (d = alldevs; d; d = d->next)
	{
		//printf("%d\t  ", num);
		cout << num << "\t";
		ifPrint(d);
		num++;
	}
	return true;

}

//返回一个以键值对的方式存储的网卡编号和网卡名
map<int, char*> makeIflistmap(pcap_if_t* alldevs) {

	map<int, char*> iflistmap;
	int num = 0;
	pcap_if_t* d;
	for (d = alldevs; d; d = d->next) {
		iflistmap[num] = d->name;
		num++;
	}
	return iflistmap;

}
