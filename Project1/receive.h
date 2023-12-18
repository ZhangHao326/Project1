#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "pcap.h"
#include <winsock2.h>
#include <string>
#include<thread>
#include<map>
#include<iostream>
#include"TimerQueue.h"
#include <chrono>
#include"Server.h"

using namespace std;
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")




// 以太网协议格式的定义
typedef struct ether_header {
	u_char ether_dhost[6];		// 目标MAC地址
	u_char ether_shost[6];		// 源MAC地址
	u_short ether_type;			// 以太网类型
}ether_header;

typedef struct neighbor_data {
	string chassis_id;
	string port_id;
	int time_to_live;
	string port_description;
	string system_name;
	string system_description;
	string system_capacities;
	string management_address;
}neighbor_data;


extern map<string, neighbor_data>mib;  //本地MIB库，key为chassis_id
extern TimerQueue timerQueue;
extern mutex mib_mutex;
extern Server myServer;
extern bool start_flag;

void delete_neighbor(std::string chassis_id);
void ethernet_protocol_packet_handle(u_char* arg, const struct pcap_pkthdr* pkt_header, const u_char* pkt_content);
void show_neighbor();
int receivePacket();
string neighbor_data_to_json(neighbor_data &neighbor);
string GetMacAddress();

string GetHostName();