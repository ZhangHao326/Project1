#pragma once
/*****************************************************************************************************************************
*	1�������׽��ֿ⣬�����׽��֣�WSAStartup()/socket()��;
*	2�����׽��ֵ�һ��IP��ַ��һ���˿��ϣ�bind()��;
*	3�����׽�������Ϊ����ģʽ�ȴ���������
*	4��������֮�󣬽����������󣬷���һ���µĶ�Ӧ�ڴ˴����ӵ��׽���(accept());
*	5���÷��ص��׽��ֺͿͻ��˽���ͨ�ţ�send()/recv()��;
*	6�����أ��ȴ���һ����������
*	7���ر��׽��֣��رռ��ص��׽��ֿ�(closesocket()/WSACleanup());
*****************************************************************************************************************************/
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <WinSock2.h>
#include <vector>
#include <mutex>
#include <string>
//using namespace std;
#pragma comment(lib,"ws2_32.lib")

class Server {
public:
	explicit Server(int port);
	~Server();
	void Init();
	void Publish(const std::string& msg);

private:
	int port_;
	SOCKET listen_fd_;
	std::vector<SOCKET> client_fds_;
	std::mutex mutex_;
};



