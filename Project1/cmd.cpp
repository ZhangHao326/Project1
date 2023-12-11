#include <iostream>
#include <string>
#include <thread>
#include"receive.h"

using namespace std;

void lldp_start() {
    timerQueue.Run();
    std::thread receiveLLDP(receivePacket);
    //cin.get();
    Sleep(5000);
    receiveLLDP.detach();
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
                cout << "close--";
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

