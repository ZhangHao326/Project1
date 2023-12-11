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
using namespace std;







map<string, neighbor_data>mib;  //����MIB�⣬keyΪchassis_id
TimerQueue timerQueue; 
mutex mib_mutex;

//��mib��ɾ���ھ�
void delete_neighbor(string chassis_id) {
	mib_mutex.lock();
	mib.erase(chassis_id);
	mib_mutex.unlock();
	cout << "";
}

// EthernetЭ�鴦��
void ethernet_protocol_packet_handle(u_char* arg, const struct pcap_pkthdr* pkt_header, const u_char* pkt_content)
{
	ether_header* ethernet_protocol;//��̫��Э��
	u_short ethernet_type;			//��̫������
	u_char* mac_string;				//��̫����ַ
	time_t local_tv_sec;
	struct tm* ltime;
	char timestr[16];
	u_char* p;                      //p,qָ�򱣴�type��length��λ
	u_char* q;
	int type;
	int length;
	int count = 1;
	//��ȡ��̫����������
	ethernet_protocol = (ether_header*)pkt_content;
	ethernet_type = ntohs(ethernet_protocol->ether_type);

	if (ethernet_type == 0x88cc) {
		//printf("==============LLDP Protocol=================\n");
		//��ʱ���ת��Ϊ��ʶ���ʽ
		/*local_tv_sec = pkt_header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);*/

		//�����š�ʱ����Ͱ�����
		//printf("==============================================================================\n");
		//printf("No.%d\ttime: %s\tlen: %ld\n", count++, timestr, pkt_header->len);
		//printf("==============================================================================\n");



		////�����
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
			//case 8:
			//	printf("Management Address: ");
			//	for (int i = 1; i <= length; i++) {
			//		printf("%d.", *(q + i));
			//	}
			//	break;
			default:
				break;

			}


			//printf("\n");

			p = p + length + 2;
			q = q + length + 2;
		}

		//TTLΪ0��ɾ���ھ�
		if (temp.time_to_live == 0) {
			timerQueue.RemoveTimer(temp.chassis_id);
			delete_neighbor(temp.chassis_id);

		}
		else {
			//����mib��
			mib_mutex.lock();
			mib[temp.chassis_id] = temp;
			mib_mutex.unlock();

			//���¼�ʱ��
			timerQueue.RemoveTimer(temp.chassis_id);
			//std::chrono::seconds duration(20);
			std::chrono::seconds duration(temp.time_to_live);
			//std::function<void(string)> callback = delete_neighbor;
			timerQueue.AddFuncAfterDuration(duration, temp.chassis_id, delete_neighbor);
			cout << "";
		}
	}

}

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
	pcap_if_t* alldevs;	//�������б�������һ�����������ݽṹ
	pcap_if_t* d;		//����ĳ��������
	pcap_t* fp;
	int res;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;


	int count = 1;
	int i = 0, inum;
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("===============Adapter List===============\n");

	//��ȡ�����豸�б�
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	//����б�
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

	//��ȡѡ����
	while (1)
	{
		printf("\nEnter the interface number (1-%d): ", i);
		scanf("%d", &inum);

		if (inum > 0 && inum <= i)
			break;
	}

	//�����û�ѡ���������
	for (d = alldevs, i = 0; i < inum - 1; ++i, d = d->next);

	//��������
	if ((fp = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "\nError openning adapter: %s\n", errbuf);
		pcap_freealldevs(alldevs);
		return -1;
	}

	//�����·�������
	if (pcap_datalink(fp) != DLT_EN10MB)
	{
		fprintf(stderr, "This program only run on Ethernet networks\n");
		pcap_close(fp);
		pcap_freealldevs(alldevs);
		return -1;
	}

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		//��ʱ
		if (res == 0)
			continue;
		//�������ݰ�
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

	//�ͷ�
	pcap_close(fp);
	pcap_freealldevs(alldevs);
	fclose(stdin);
	return 0;
}