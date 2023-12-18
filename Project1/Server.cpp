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
	//��ʼ��WSA
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA wsaData;//WSADATA�ṹ������ĵ�ֵַ

	//�ɹ�ʱ�᷵��0��ʧ��ʱ���ط���Ĵ������ֵ
	assert(WSAStartup(sockVersion, &wsaData) == 0);
	
	//�����׽���
	listen_fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert(listen_fd_ != INVALID_SOCKET);

	//��IP�Ͷ˿�
	sockaddr_in sin;//ipv4��ָ��������ʹ��struct sockaddr_in���͵ı���
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port_);//���ö˿ڡ�htons��������unsigned short intת��Ϊ�����ֽ�˳��
	sin.sin_addr.S_un.S_addr = INADDR_ANY;//IP��ַ���ó�INADDR_ANY����ϵͳ�Զ���ȡ������IP��ַ

	//bind������һ����ַ���е��ض���ַ����socket��
	assert(::bind(listen_fd_, (LPSOCKADDR)&sin, sizeof(sin)) != SOCKET_ERROR);

	//��ʼ����
	assert(listen(listen_fd_, 5) != SOCKET_ERROR);

	//ѭ����������
	SOCKET sclient;
	sockaddr_in remoteAddr;//sockaddr_in������socket����͸�ֵ,sockaddr���ں�������
	int nAddrlen = sizeof(remoteAddr);
	while (start_flag)
	{
		sclient = accept(listen_fd_, (sockaddr*)&remoteAddr, &nAddrlen);
		if (sclient == INVALID_SOCKET)
		{
			std::cout << "accept error !" << endl;
			continue;
		}
		std::cout << "���յ�һ�����ӣ�" << inet_ntoa(remoteAddr.sin_addr) << endl;
		{
			string dnsname = "local "+GetHostName() + ".";
			transform(dnsname.begin(), dnsname.end(), dnsname.begin(), ::tolower);
			string local_message;
			//string mac = GetMacAddress();

			//string local_message = "{\"chassis_id:\"" + dnsname + ",\"mac_address:\"" + mac + "}";
			//const char* local_message_= local_message.c_str();

			//����
			//send(sclient, local_message_, strlen(local_message_), 0);

			//�ھ�
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
