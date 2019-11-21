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

//����Npcap��DLL�ļ�·��,��������DLL�ӳټ���
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

//��ȡ�����б�
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

//��������ַ�����ʽmacת��ʮ��������
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

//���ݴ����pcap������Ϣ�ṹ���������Ϣ
bool ifPrint(pcap_if_t* d) {

	pcap_addr_t* a;
	//��ʵ������Ҫ���������
	cout << d->name<<"\t";
	cout << d->description<<"\t";
	for (a = d->addresses; a; a = a->next) {

		switch (a->addr->sa_family)
		{
		//ֻ��עipv4
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

//�г�����������Ϣ
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

//����һ���Լ�ֵ�Եķ�ʽ�洢��������ź�������
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
