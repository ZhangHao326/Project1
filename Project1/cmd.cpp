#include <iostream>
#include <string>
#include <thread>
#include"receive.h"

using namespace std;

void server_start() {
    myServer.Init();
}
void lldp_start() {
    start_flag = 1;
    timerQueue.Run();
    thread my_server(server_start);
    thread receiveLLDP(receivePacket);
    //cin.get();
    Sleep(5000);
    //my_server.
    my_server.detach();
    receiveLLDP.detach();
}
void lldp_close() {
    
    //·¢ËÍshutdown°ü


    start_flag = 0;
}
int main() {

    while (true) {
        cout << ">> ";
        string command;
        getline(cin, command);

        string cmd = command.substr(0, command.find(' '));
        string arg = command.substr(command.find(' ') + 1);

        if (command == "exit") {
            break;
        }
        // Execute the command
        if (cmd == "LLDP" || cmd == "lldp") {
            if (arg == "start")
            {
                lldp_start();
            }
            else if (arg == "close")
            {
                
                lldp_close();
            }
            else if (arg == "show")
            {
                show_neighbor();
            }
            else {
                cout << "Invalid command" << endl;
            }
        }
     else {
            cout << "" << endl;
        }



        // Your code here
    }

    return 0;
}

