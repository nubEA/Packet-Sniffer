#include <iostream>
#include "socket_manager.hpp"
#include "packet_parser.hpp"
#include "packet_structure.hpp"

int main(int argc, char* argv[]){
    
    std::string interface{"wlp0s20f3"};
    std::string protocol{};
    int portFilter{-1};
    
    if(argc > 1)
    {
        interface = argv[1];
        if(argc > 2) protocol = argv[2];
        if(argc > 3) portFilter = std::stoi(argv[3]);
    }

    SocketManager manager(interface);

    std::vector<char> buffer(64*1024);
    size_t size = sizeof(buffer);

    while(true){
        int bytesReceived = manager.capture_packet(buffer,size);
        if(bytesReceived > 0)
        {
            Packet packet = PacketParser::parse_packet(buffer,bytesReceived);
        }

    }   
}