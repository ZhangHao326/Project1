#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "pcap.h"
#include "Header.h"
#include <winsock2.h>
#include <string>
#include<map>
#include<iostream>

extern int run_loop;
void lldp();
void wait(int sec);
void interrupt();
void loop();
void sendPacket();
void send_lldp_close_packet();