#include <iostream>
#include "socket_manager.hpp"
#include "packet_parser.hpp"
#include "packet_structure.hpp"
#include "http_parser.hpp"

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
    
    try
    {
        SocketManager manager(interface);
        std::vector<char> buffer(64*1024);
        size_t size = buffer.size();
        
        while(true){
            int bytesReceived = manager.capture_packet(buffer,size);
            if(bytesReceived > 0)
            {
                try
                {
                    Packet packet = PacketParser::parse_packet(buffer,bytesReceived);
                }
                catch(const std::exception& e)
                {
                    std::cerr << e.what() << '\n';
                }
            }
        }        
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}