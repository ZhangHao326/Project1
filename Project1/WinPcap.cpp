
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "pcap.h"
#include "Header.h"
#include <winsock2.h>
#include <string.h>
#include<thread>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")

#define LINE_LEN 16
#define MAX_ADDR_LEN 16

FILE *file = 0;

// 以太网协议格式的定义
typedef struct ether_header {
	u_char ether_dhost[6];		// 目标MAC地址
	u_char ether_shost[6];		// 源MAC地址
	u_short ether_type;			// 以太网类型
}ether_header;


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

	//printf("==============Ethernet Protocol=================\n");
	if (ethernet_type == 0x88cc) {
		printf("==============LLDP Protocol=================\n");
		//将时间戳转化为可识别格式
		local_tv_sec = pkt_header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

		//输出编号、时间戳和包长度
		printf("==============================================================================\n");
		printf("No.%d\ttime: %s\tlen: %ld\n", count++, timestr, pkt_header->len);
		printf("==============================================================================\n");
	
		//输出包
		for (int i = 0; i < pkt_header->caplen; ++i)
		{
			printf("%.2x ", pkt_content[i]);
			if (i % 16 == 15)
				printf("\n");
		}
		printf("\n");


		//以太网目标地址
		mac_string = ethernet_protocol->ether_dhost;

		printf("Destination Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
			*mac_string,
			*(mac_string + 1),
			*(mac_string + 2),
			*(mac_string + 3),
			*(mac_string + 4),
			*(mac_string + 5));

		//以太网源地址
		mac_string = ethernet_protocol->ether_shost;

		printf("Source Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
			*mac_string,
			*(mac_string + 1),
			*(mac_string + 2),
			*(mac_string + 3),
			*(mac_string + 4),
			*(mac_string + 5));

		p = (u_char*)(pkt_content + 14);
		q = (u_char*)(pkt_content + 15);

		while (1) {
			type = (*p) / 2;
			length = ((*p) % 2)*256 + *q;

			if (type == 0)
				break;

			switch (type) {
			case 1:
				printf("Chassis ID: ");
				for (int i = 1; i <= length; i++) {
					printf("%02x ", *(q + i));
				}
				break;
			case 2:
				printf("Port ID: ");
				for (int i = 1; i <= length; i++) {
					printf("%02x ", *(q + i));
				}
				break;
			case 3:
				printf("Time To Live: ");
				for (int i = 1; i <= length; i++) {
					printf("%d", *(q + i));
				}
				break;
			case 4:
				printf("Port Description: ");
				for (int i = 1; i <= length; i++) {
					printf("%c", *(q + i));
				}
				break;
			case 5:
				printf("System Name: ");
				for (int i = 1; i <= length; i++) {
					printf("%c", *(q + i));
				}
				break;
			case 6:
				printf("System Description: ");
				for (int i = 1; i <= length; i++) {
					printf("%c", *(q + i));
				}
				break;
			case 7:
				printf("System Capabilities: ");
				for (int i = 1; i <= length; i++) {
					printf("%2x ", *(q + i));
				}
				break;
			case 8:
				printf("Management Address: ");
				for (int i = 1; i <= length; i++) {
					printf("%d.", *(q + i));
				}
				break;
			case 127:
				printf("Organizationally Specific TLVs: ");
				for (int i = 1; i <= length; i++) {
					printf("%2x ", *(q + i));
				}
				break;
			default:
				printf("Unknown type: ");
				for (int i = 1; i <= length; i++) {
					printf("%c", *(q + i));
				}
				break;

			}

			printf("\n");

			p = p + length + 2;
			q = q + length + 2;
		}
	}
}

HINSTANCE dllHandle;

int run_loop = 1;



void lldp() {
	dbg << "Job run";
	FIXED_INFO* pFixedInfo;
	ULONG ulOutBufLen;

	DWORD dwSize = 0;
	DWORD dwRetVal = 0;

	unsigned int i, j;

	MIB_IF_TABLE2* pIfTable;
	MIB_IF_ROW2* pIfRow;

	string dnsname;

	pFixedInfo = (FIXED_INFO*)MALLOC(sizeof(FIXED_INFO));
	pIfTable = (MIB_IF_TABLE2*)MALLOC(sizeof(MIB_IF_TABLE2));

	if (pFixedInfo == NULL) {
		dbg << "Error allocating memory needed to call GetNetworkParams";
		goto FreeMemory;
	}
	ulOutBufLen = sizeof(FIXED_INFO);

	if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pFixedInfo);
		pFixedInfo = (FIXED_INFO*)MALLOC(ulOutBufLen);
		if (pFixedInfo == NULL) {
			dbg << "Error allocating memory needed to call GetNetworkParams\n";
			goto FreeMemory;
		}
	}

	if (dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen) != NO_ERROR) {
		dbg << "Error call GetNetworkParams";
		goto FreeMemory;
	}
	dnsname = pFixedInfo->HostName + string(".") + pFixedInfo->DomainName;
	transform(dnsname.begin(), dnsname.end(), dnsname.begin(), ::tolower);
	dbg << "Hostname: " << dnsname;

	struct hostent* Host;
	struct in_addr addr;
	WSADATA wsaData;
	int iResult;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		dbg << "WSAStartup failed: " << iResult;
		goto FreeMemory;
	}
	Host = gethostbyname(dnsname.c_str());
	i = 0;
	if (Host->h_addrtype == AF_INET && Host->h_addr_list[0] != 0)
	{
		addr.s_addr = *(u_long*)Host->h_addr_list[0];
	}
	dbg << "IP Address :" << inet_ntoa(addr);

	// Allocate memory for our pointers.
	if (pIfTable == NULL) {
		dbg << "Error allocating memory needed to call GetIfTable2";
		goto FreeMemory;
	}

	// Make an initial call to GetIfTable2 to get the
	// necessary size into dwSize
	dwSize = sizeof(MIB_IF_TABLE2);
	if (GetIfTable2(&pIfTable) == ERROR_NOT_ENOUGH_MEMORY) {
		FREE(pIfTable);
		pIfTable = (MIB_IF_TABLE2*)MALLOC(dwSize);
		if (pIfTable == NULL) {
			dbg << "Error allocating memory needed to call GetIfTable2";
			goto FreeMemory;
		}
	}
	if ((dwRetVal = GetIfTable2(&pIfTable)) == NO_ERROR) {
		for (i = 0; i < pIfTable->NumEntries; i++) {
			pIfRow = (MIB_IF_ROW2*)&pIfTable->Table[i];
			if (pIfRow->PhysicalMediumType == NdisPhysicalMedium802_3
				&& pIfRow->MediaType == NdisMedium802_3
				&& pIfRow->PhysicalAddressLength
				&& !pIfRow->InterfaceAndOperStatusFlags.FilterInterface
				&& pIfRow->InterfaceAndOperStatusFlags.HardwareInterface) {

				OLECHAR* guid;
				if (StringFromCLSID(pIfRow->InterfaceGuid, &guid) != S_OK) {
					dbg << "Failed get GUID to adapter index: " << pIfRow->InterfaceIndex;
					continue;
				}
				string rpcap = "rpcap://\\Device\\NPF_";
				USES_CONVERSION;
				rpcap.append(W2A(guid));
				FREE(guid);

				pcap_t* fp;
				char errbuf[PCAP_ERRBUF_SIZE];
				dbg << "Open pcap: " << rpcap;

				//打开适配器
				if ((fp = pcap_open_live(rpcap.c_str(), 65536, 4, 1000, errbuf)) == NULL)
				{
					dbg << "Unable to open the adapter. " << rpcap.c_str() << " is not supported by WinPcap";
					continue;
				}
				//if ((fp = pcap_open(rpcap.c_str(),
				//	100,                // portion of the packet to capture (only the first 100 bytes)
				//	PCAP_OPENFLAG_NOCAPTURE_RPCAP,
				//	1000,               // read timeout
				//	NULL,               // authentication on the remote machine
				//	errbuf              // error buffer
				//)) == NULL) {
				//	dbg << "Unable to open the adapter. " << rpcap.c_str() << " is not supported by WinPcap";
				//	continue;
				//}

				vector<u_char> packet;
				// LLDP_MULTICAST
				packet.push_back(0x01);
				packet.push_back(0x80);
				packet.push_back(0xc2);
				packet.push_back(0x00);
				packet.push_back(0x00);
				packet.push_back(0x0e);

				// SRC MAC
				string strmak;
				for (j = 0; j < (int)pIfRow->PhysicalAddressLength; j++) {
					packet.push_back((u_char)pIfRow->PhysicalAddress[j]);
				}
				dbg << "Building packet: SRC MAC: " << hex
					<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[0] << ":"
					<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[1] << ":"
					<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[2] << ":"
					<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[3] << ":"
					<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[4] << ":"
					<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[5]
					<< dec << setw(1);

				// ETHERNET_TYPE_LLDP
				packet.push_back(0x88);
				packet.push_back(0xcc);

				dbg << "Building packet: CHASSIS ID: " << dnsname;
				packet.push_back(0x02); // chassis id
				packet.push_back((u_char)(dnsname.length() + 1));
				packet.push_back(0x07); // locally assigned
				for (int j = 0; j < dnsname.length(); ++j) {
					packet.push_back((u_char)dnsname.c_str()[j]);
				}

				// PORT SUBTYPE
				wstring TifAlias(pIfRow->Alias);
				char alias[sizeof(pIfRow->Alias)];
				sprintf(alias, "%ws", pIfRow->Alias);
				//string ifAlias(TifAlias.begin(), TifAlias.end());
				bool ansi = TRUE;
				for (j = 0; j < TifAlias.size(); j++) {
					if ((u_char)alias[j] > 127)
					{
						ansi = FALSE;
						break;
					}
				}
				packet.push_back(0x04); // port id
				if (TifAlias.size() && ansi) {
					packet.push_back(1 + TifAlias.size()); // size: 1 + sizeof(ifName)
					packet.push_back(0x01); // type = ifAlias (IETF RFC 2863)
					dbg << "Building packet: PORT ID: " << alias;
					for (int j = 0; j < TifAlias.size(); j++) {
						packet.push_back((u_char)alias[j]);
					}
				}
				else {
					dbg << "Building packet: PORT ID: " << hex
						<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[0] << ":"
						<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[1] << ":"
						<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[2] << ":"
						<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[3] << ":"
						<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[4] << ":"
						<< setfill('0') << setw(2) << (int)pIfRow->PhysicalAddress[5]
						<< dec << setw(1);

					packet.push_back(0x07); // size 1+6
					packet.push_back(0x03); // type = mac address
					for (int j = 0; j < 6; ++j) {
						packet.push_back(pIfRow->PhysicalAddress[j]);
					}
				}

				// TTL
				packet.push_back(0x06); // TTL
				packet.push_back(0x02); // size 1+1
				packet.push_back(0x00); // 120 sec
				packet.push_back(0x78);

				// Port description
				wstring TDescription(pIfRow->Description);
				string Description(TDescription.begin(), TDescription.end());
				dbg << "Building packet: Port Desc: " << Description;
				packet.push_back(0x08); // Port Description
				packet.push_back(Description.size()); // Description length
				for (int j = 0; j < Description.size(); ++j) {
					packet.push_back((u_char)Description[j]);
				}

				// System name
				dbg << "Building packet: Sys Name: " << dnsname;
				packet.push_back(0x0a); // System name
				packet.push_back((u_char)dnsname.length()); // Name length
				for (int j = 0; j < dnsname.length(); ++j) {
					packet.push_back(dnsname[j]);
				}

				// System description
				string osname("Windows");
				dbg << "Building packet: Sys Desc: " << osname;
				packet.push_back(0x0c); // System desc
				packet.push_back((u_char)osname.length()); // Name length
				for (int j = 0; j < osname.length(); ++j) {
					packet.push_back((u_char)osname[j]);
				}

				// Caps
				packet.push_back(0x0e); // Sys caps
				packet.push_back(0x04); // size 2+2
				packet.push_back(0x00); //
				packet.push_back(0x80); // station only
				packet.push_back(0x00); //
				packet.push_back(0x80); // station only

				// Management address
				dbg << "Building packet: Management address: " << inet_ntoa(addr);
				packet.push_back(0x10); // Management addr
				packet.push_back(0x0c); // size 12
				packet.push_back(0x05); // addr len 1+4
				packet.push_back(0x01); // addr subtype: ipv4
				packet.push_back((u_char)addr.S_un.S_un_b.s_b1); // ip
				packet.push_back((u_char)addr.S_un.S_un_b.s_b2); // ip
				packet.push_back((u_char)addr.S_un.S_un_b.s_b3); // ip
				packet.push_back((u_char)addr.S_un.S_un_b.s_b4); // ip
				dbg << "Building packet: Management address: if subtype - ifIndex: " << pIfRow->InterfaceIndex;
				packet.push_back(0x02); // if subtype: ifIndex
				BYTE* pbyte = (BYTE*)&(pIfRow->InterfaceIndex);
				packet.push_back(pbyte[3]); // id
				packet.push_back(pbyte[2]); // id
				packet.push_back(pbyte[1]); // id
				packet.push_back(pbyte[0]); // id
				packet.push_back(0x00); // oid len 0

				// IEEE 802.3 - MAC/PHY Configuration/Status
				packet.push_back(0xfe); //
				packet.push_back(0x09); //
				packet.push_back(0x00); //
				packet.push_back(0x12); //
				packet.push_back(0x0f); //
				packet.push_back(0x01); //
				packet.push_back(0x02); //
				packet.push_back(0x80); //
				packet.push_back(0x00); //
				packet.push_back(0x00); //
				packet.push_back(0x1e); //

				// IEEE 802.3 - Maximum Frame Size
				packet.push_back(0xfe); //
				packet.push_back(0x06); //
				packet.push_back(0x00); //
				packet.push_back(0x12); //
				packet.push_back(0x0f); //
				packet.push_back(0x04); //
				packet.push_back(0x05); //
				packet.push_back(0xee); //

				// TIA TR-41 Committee - Media Capabilities
				packet.push_back(0xfe); //
				packet.push_back(0x07); //
				packet.push_back(0x00); //
				packet.push_back(0x12); //
				packet.push_back(0xbb); //
				packet.push_back(0x01); //
				packet.push_back(0x01); //
				packet.push_back(0xee); //
				packet.push_back(0x03); //

				// TIA TR-41 Committee - Network Policy
				packet.push_back(0xfe); //
				packet.push_back(0x08); //
				packet.push_back(0x00); //
				packet.push_back(0x12); //
				packet.push_back(0xbb); //
				packet.push_back(0x02); //
				packet.push_back(0x06); //
				packet.push_back(0x80); //
				packet.push_back(0x00); //
				packet.push_back(0x00); //

				// TIA TR-41 Committee - Network Policy
				packet.push_back(0xfe); //
				packet.push_back(0x08); //
				packet.push_back(0x00); //
				packet.push_back(0x12); //
				packet.push_back(0xbb); //
				packet.push_back(0x02); //
				packet.push_back(0x07); //
				packet.push_back(0x80); //
				packet.push_back(0x00); //
				packet.push_back(0x00); //

				// End of LLDPDU
				packet.push_back(0x00); // type
				packet.push_back(0x00); // len 0

				// Send down the packet
				dbg << "Sending packet (size: " << packet.size() << ")";
				if (pcap_sendpacket(fp, packet.data(), packet.size()) != 0) {
					fprintf(stderr, "\nError sending the packet: \n");
					fprintf(stderr, pcap_geterr(fp));
					fprintf(stderr, "\n");
				}

				dbg << "Closing pcap";
				pcap_close(fp);
				packet.clear();
			}
		}
	}
FreeMemory:
	if (pFixedInfo)
		FREE(pFixedInfo);
	if (pIfTable)
		FREE(pIfTable);
}

void wait(basic_ostream<char>* progress, int sec) {
	*progress << "Sleeping " << sec << "sec";
	for (int i = 0; i < sec; ++i) {
		if (!run_loop) {
			dbg << "Exiting";
			exit(0);
		}
		Sleep(1000);
		*progress << ".";
	}
}

void loop() {
	//loadpcap();
	while (true) {
		lldp();
		wait(&(dbg), 30);
	}
}


void interrupt() {
	run_loop = 0;
}


void sendPacket() {
	int a = 0;
	int action = 0;
	static SERVICE_TABLE_ENTRY Services[] = {
			{(LPSTR)SVCNAME , (LPSERVICE_MAIN_FUNCTION)md_service_main},
			{0}
	};

	// trying to start as a service
	if (!StartServiceCtrlDispatcher(Services)) {
		_dbg_cfg(true);
		loop();
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

	printf("The program is working......\n");
	printf("The capture file is saving as 'data.txt'\n");
	printf("You can input 'ctrl + C' to stop the program\n");

	if ((file = freopen("data.txt", "w", stdout)) == 0)
		printf("Cannot open the file.\n");

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
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
		if (file)
			fclose(file);
		return -1;
	}

	//释放
	pcap_close(fp);
	pcap_freealldevs(alldevs);
	fclose(stdin);
	if (file)
		fclose(file);
}
int main()
{
	std::thread sendLLDP(sendPacket);
	std::thread receiveLLDP(receivePacket);
	sendLLDP.join();
	receiveLLDP.join();
	return 0;
}