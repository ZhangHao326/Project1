#pragma once
/*****************************************************************************************************************************
*	1、加载套接字库，创建套接字（WSAStartup()/socket()）;
*	2、绑定套接字到一个IP地址和一个端口上（bind()）;
*	3、将套接字设置为监听模式等待连接请求；
*	4、请求到来之后，接受连接请求，返回一个新的对应于此次连接的套接字(accept());
*	5、用返回的套接字和客户端进行通信（send()/recv()）;
*	6、返回，等待另一个连接请求
*	7、关闭套接字，关闭加载的套接字库(closesocket()/WSACleanup());
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



