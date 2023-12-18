#include "Server.h"

#include <assert.h>
#include"Header.h"
#include"receive.h"
Server::Server(int port) : port_(port), listen_fd_(0) {}

Server::~Server() {
	for (auto& client_fd : client_fds_) {
		closesocket(client_fd);
	}
	closesocket(listen_fd_);
	WSACleanup();
}

void Server::Init() {
	//初始化WSA
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA wsaData;//WSADATA结构体变量的地址值

	//成功时会返回0，失败时返回非零的错误代码值
	assert(WSAStartup(sockVersion, &wsaData) == 0);
	
	//创建套接字
	listen_fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert(listen_fd_ != INVALID_SOCKET);

	//绑定IP和端口
	sockaddr_in sin;//ipv4的指定方法是使用struct sockaddr_in类型的变量
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port_);//设置端口。htons将主机的unsigned short int转换为网络字节顺序
	sin.sin_addr.S_un.S_addr = INADDR_ANY;//IP地址设置成INADDR_ANY，让系统自动获取本机的IP地址

	//bind函数把一个地址族中的特定地址赋给socket。
	assert(::bind(listen_fd_, (LPSOCKADDR)&sin, sizeof(sin)) != SOCKET_ERROR);

	//开始监听
	assert(listen(listen_fd_, 5) != SOCKET_ERROR);

	//循环接收数据
	SOCKET sclient;
	sockaddr_in remoteAddr;//sockaddr_in常用于socket定义和赋值,sockaddr用于函数参数
	int nAddrlen = sizeof(remoteAddr);
	while (start_flag)
	{
		sclient = accept(listen_fd_, (sockaddr*)&remoteAddr, &nAddrlen);
		if (sclient == INVALID_SOCKET)
		{
			std::cout << "accept error !" << endl;
			continue;
		}
		std::cout << "接收到一个连接：" << inet_ntoa(remoteAddr.sin_addr) << endl;
		{
			string dnsname = "local "+GetHostName() + ".";
			transform(dnsname.begin(), dnsname.end(), dnsname.begin(), ::tolower);
			string local_message;
			//string mac = GetMacAddress();

			//string local_message = "{\"chassis_id:\"" + dnsname + ",\"mac_address:\"" + mac + "}";
			//const char* local_message_= local_message.c_str();

			//本机
			//send(sclient, local_message_, strlen(local_message_), 0);

			//邻居
			string s = "data";
			s += "$"+dnsname+"$";
			mib_mutex.lock();
			for (auto it = mib.begin(); it != mib.end(); ++it) {
				if (it->first == dnsname) {
					neighbor_data value = it->second;
					s += value.port_id;
				}
			}
			
			for (auto it = mib.begin(); it != mib.end(); ++it) {
				if (it->first != dnsname) {
					neighbor_data value = it->second;
					s += "$"+value.chassis_id + "$" + value.port_id;
				}
			}
			//string s = "data,";
			//s += dnsname + ",";
			//s += "Windows,";
			//mib_mutex.lock();
			//for (auto it = mib.begin(); it != mib.end(); ++it) {
			//	if (it->first != dnsname) {
			//		neighbor_data value = it->second;
			//		s += value.chassis_id + "," + value.system_description+",";
			//	}
			//}
			mib_mutex.unlock();
			s += "$";
			const char* s_ =s.c_str();
			send(sclient, s_, strlen(s_), 0);
			std::unique_lock<std::mutex> lock(mutex_);
			client_fds_.push_back(sclient);
		}
	}
}

void Server::Publish(const std::string& msg) {
	std::vector<SOCKET> client_fds_copy;
	{
		std::unique_lock<std::mutex> lock(mutex_);
		client_fds_copy = client_fds_;
	}
	for (auto& client_fd : client_fds_) {
		send(client_fd, msg.c_str(), msg.size(), NULL);
	}
}
