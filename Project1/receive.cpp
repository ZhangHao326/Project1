#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "pcap.h"
#include <winsock2.h>
#include <string>
#include<thread>
#include<map>
#include<iostream>
#include"TimerQueue.h"
#include <chrono>
#include "receive.h"
#include <iostream>
#include <WinSock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <assert.h>
#include<Winsock2.h>
#include<Windows.h>
#include"Header.h"
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib,"ws2_32.lib")
using namespace std;







map<string, neighbor_data>mib;  //本地MIB库，key为chassis_id
TimerQueue timerQueue; 
mutex mib_mutex;
Server myServer(1234);
bool start_flag = 0;

//从mib库删除邻居
void delete_neighbor(string chassis_id) {
	mib_mutex.lock();
	mib.erase(chassis_id);
	mib_mutex.unlock();
}

// Ethernet协议处理
void ethernet_protocol_packet_handle(u_char* arg, const struct pcap_pkthdr* pkt_header, const u_char* pkt_content)
{
	ether_header* ethernet_protocol;//以太网协议
	u_short ethernet_type;			//以太网类型
	u_char* mac_string;				//以太网地址
	time_t local_tv_sec;
	struct tm* ltime;
	char timestr[16];
	u_char* p;                      //p,q指向保存type和length的位
	u_char* q;
	int type;
	int length;
	int count = 1;
	//获取以太网数据内容
	ethernet_protocol = (ether_header*)pkt_content;
	ethernet_type = ntohs(ethernet_protocol->ether_type);

	if (ethernet_type == 0x88cc) {
		//printf("==============LLDP Protocol=================\n");
		//将时间戳转化为可识别格式
		/*local_tv_sec = pkt_header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);*/

		//输出编号、时间戳和包长度
		//printf("==============================================================================\n");
		//printf("No.%d\ttime: %s\tlen: %ld\n", count++, timestr, pkt_header->len);
		//printf("==============================================================================\n");



		////输出包
		//for (int i = 0; i < pkt_header->caplen; ++i)
		//{
		//	printf("%.2x ", pkt_content[i]);
		//	if (i % 16 == 15)
		//		printf("\n");
		//}
		//printf("\n");


		p = (u_char*)(pkt_content + 14);
		q = (u_char*)(pkt_content + 15);
		neighbor_data temp;
		temp.chassis_id = "";
		temp.port_id = "";
		temp.time_to_live = 0;
		temp.port_description = "";
		temp.management_address = "";
		temp.system_capacities = "";
		temp.system_name = "";
		temp.system_description = "";

		while (1) {
			type = (*p) / 2;
			length = ((*p) % 2) * 256 + *q;

			if (type == 0)
				break;

			switch (type) {
			case 1:
				//subtype
				if (*(q + 1) == 4) {
					//ostringstream macStream;
					temp.chassis_id += "mac ";
					for (int i = 2; i <= length; i++) {
						char hex_char[3];
						sprintf(hex_char, "%02x", *(q + i));
						temp.chassis_id += hex_char;
						if (i < length) {
							temp.chassis_id += ":";
						}
					}
				}
				else if (*(q + 1) == 7) {
					temp.chassis_id += "local ";
					for (int i = 2; i <= length; i++) {

						temp.chassis_id += *(q + i);
					}
				}
				break;
			case 2:
				if (*(q + 1) == 1) {
					temp.port_id += "ifalias ";
					for (int i = 2; i <= length; i++) {
						temp.port_id += *(q + i);
					}
				}
				else if (*(q + 1) == 3) {
					temp.port_id += "mac ";
					for (int i = 2; i <= length; i++) {
						char hex_char[3];
						sprintf(hex_char, "%02x", *(q + i));
						temp.port_id += hex_char;
						if (i < length) {
							temp.port_id += ":";
						}
					}
				}
				break;
			case 3:
				for (int i = 1; i <= length; i++) {
					temp.time_to_live = temp.time_to_live * 10 + *(q + i);
				}
				break;
			case 4:
				for (int i = 1; i <= length; i++) {
					temp.port_description += char(*(q + i));
				}
				break;
			case 5:
				//printf("System Name: ");
				for (int i = 1; i <= length; i++) {
					temp.system_name += *(q + i);
				}
				break;
			case 6:
				//printf("System Description: ");
				for (int i = 1; i <= length; i++) {
					//printf("%c", *(q + i));
					temp.system_description += *(q + i);
				}
				break;
			//case 7:
			//	printf("System Capabilities: ");
			//	for (int i = 1; i <= length; i++) {
			//		printf("%2x ", *(q + i));
			//	}
			//	break;
			case 8:
			//	printf("Management Address: ");
				//int mag_len = *(q + 1);
				
				//subtype: ipv4
				if (*(q + 2) == 1) {
					temp.management_address += "ipv4 ";
					for (int i = 3; i < 7; i++) {
						int j = *(q + i);
						temp.management_address += to_string(j);
						if (i < 6) {
							temp.management_address += ".";
						}

					}
					
				}
				break;
			default:
				break;

			}


			//printf("\n");

			p = p + length + 2;
			q = q + length + 2;
		}

		//TTL为0，删除邻居
		if (temp.time_to_live == 0) {
			timerQueue.RemoveTimer(temp.chassis_id);
			delete_neighbor(temp.chassis_id);

		}
		else {
			//更新mib库
			mib_mutex.lock();
			mib[temp.chassis_id] = temp;
			
			mib_mutex.unlock();

			//更新计时器
			timerQueue.RemoveTimer(temp.chassis_id);
			//std::chrono::seconds duration(20);
			std::chrono::seconds duration(temp.time_to_live);
			//std::function<void(string)> callback = delete_neighbor;
			timerQueue.AddFuncAfterDuration(duration, temp.chassis_id, delete_neighbor);
			//cout << "";
		}
	}

}

//打印邻居信息
void show_neighbor() {
	for (auto it = mib.begin(); it != mib.end(); ++it) {
		neighbor_data value = it->second;
		cout << "---------------------------------------" << endl;
		cout <<"Chassis ID: " << value.chassis_id<<endl;
		cout << "Port ID: " << value.port_id << endl;
		cout << "Time to Live: " << value.time_to_live << endl;
		if(value.port_description!="")
			cout << "Port Description: " << value.port_description << endl;
		if (value.system_name != "")
			cout << "System name: " << value.system_name << endl;
		if (value.system_description != "")
			cout << "System Description: " << value.system_description << endl;
		if (value.system_capacities != "")
			cout << "System Capacities: " << value.system_capacities << endl;
		if (value.management_address != "")
			cout << "Management Address: " << value.management_address << endl;
	}
}


int receivePacket() {
	pcap_if_t* alldevs;	//适配器列表，它是一个链表的数据结构
	pcap_if_t* d;		//保存某个适配器
	pcap_t* fp;
	int res;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;


	int count = 1;
	int i = 0, inum;
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("===============Adapter List===============\n");

	//获取本地设备列表
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	//输出列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	//获取选择编号
	while (1)
	{
		printf("\nEnter the interface number (1-%d): ", i);
		scanf("%d", &inum);

		if (inum > 0 && inum <= i)
			break;
	}

	//跳到用户选择的适配器
	for (d = alldevs, i = 0; i < inum - 1; ++i, d = d->next);

	//打开适配器
	if ((fp = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "\nError openning adapter: %s\n", errbuf);
		pcap_freealldevs(alldevs);
		return -1;
	}

	//检查链路层的类型
	if (pcap_datalink(fp) != DLT_EN10MB)
	{
		fprintf(stderr, "This program only run on Ethernet networks\n");
		pcap_close(fp);
		pcap_freealldevs(alldevs);
		return -1;
	}

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0&&start_flag)
	{
		//超时
		if (res == 0)
			continue;
		//分析数据包
		ethernet_protocol_packet_handle(NULL, header, pkt_data);
	}

	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
		pcap_close(fp);
		pcap_freealldevs(alldevs);
		fclose(stdin);
		return -1;
	}

	//释放
	pcap_close(fp);
	pcap_freealldevs(alldevs);
	fclose(stdin);
	return 0;
}

//把邻居信息转化为json格式
string neighbor_data_to_json(neighbor_data &neighbor) {
	string s="{";
	s += "\"chassis_id\":";
	s += neighbor.chassis_id;
	s+= ",\"port_id\":";
	s += neighbor.port_id;
	s+= ",\"time_to_live\":";
	s += neighbor.time_to_live;
	if (neighbor.port_description != "") {
		s += ",\"port_description\":";
		s += neighbor.port_description;
	}
	if (neighbor.system_name != "") {
		s += ",\"system_name\":";
		s += neighbor.system_name;
	}
	if (neighbor.system_description != "") {
		s += ",\"system_description\":";
		s += neighbor.system_description;
	}
	if (neighbor.system_capacities != "") {
		s += ",\"system_capacities\":";
		s += neighbor.system_capacities;
	}
	if (neighbor.management_address != "") {
		s += ",\"management_address\":";
		s += neighbor.management_address;
	}
	s += "}";
	return s;
}

string GetMacAddress()
{
	std::string macAddress;

	// 初始化Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		std::cerr << "Failed to initialize Winsock" << std::endl;
		return macAddress;
	}

	// 获取接口信息
	DWORD bufferSize = 0;
	if (GetAdaptersInfo(NULL, &bufferSize) != ERROR_BUFFER_OVERFLOW)
	{
		std::cerr << "Failed to get adapter info" << std::endl;
		WSACleanup();
		return macAddress;
	}

	std::vector<char> buffer(bufferSize);
	PIP_ADAPTER_INFO adapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(&buffer[0]);
	if (GetAdaptersInfo(adapterInfo, &bufferSize) != NO_ERROR)
	{
		std::cerr << "Failed to get adapter info" << std::endl;
		WSACleanup();
		return macAddress;
	}

	// 遍历接口信息，获取第一个以太网卡的MAC地址
	while (adapterInfo)
	{
		if (adapterInfo->Type == MIB_IF_TYPE_ETHERNET)
		{
			char mac[18];
			sprintf_s(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
				adapterInfo->Address[0], adapterInfo->Address[1], adapterInfo->Address[2],
				adapterInfo->Address[3], adapterInfo->Address[4], adapterInfo->Address[5]);
			macAddress = mac;
			break;
		}
		adapterInfo = adapterInfo->Next;
	}

	WSACleanup();

	return macAddress;
}


std::string GetHostName()
{
	std::string hostname;

	// 初始化Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		std::cerr << "Failed to initialize Winsock" << std::endl;
		return hostname;
	}

	char buffer[256];
	if (gethostname(buffer, sizeof(buffer)) == 0)
	{
		hostname = buffer;
	}
	else
	{
		std::cerr << "Failed to get hostname" << std::endl;
	}

	WSACleanup();

	return hostname;
}
