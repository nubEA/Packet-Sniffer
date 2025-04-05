#include <iostream>
#include "socket_manager.hpp"
#include "packet_parser.hpp"
#include "packet_structure.hpp"
#include "http_parser.hpp"
#include "packet_printer.hpp"   

void print_correct_cli_format() {
    std::cout << "Usage: "
              << BOLD << "./sniffer" << RESET                
              << " " << YELLOW << "<interface>" << RESET     
              << " [" << CYAN << "-p" << RESET << " | " << CYAN << "--protocol" << RESET 
              << " " << YELLOW << "<protocol>" << RESET    
              << "]"
              << " [" << CYAN << "--port" << RESET
              << " " << YELLOW << "<port>" << RESET         
              << "]" << std::endl;

    std::cout << "Options:" << std::endl;
    std::cout << "  " << YELLOW << "<interface>" << RESET << "\t\t: Network interface name. (type ifconfig on terminal to get interface names) (e.g. wlp0, eth0, lo)" << std::endl;
    std::cout << "  " << CYAN << "-p, --protocol <proto>" << RESET << ": Filter by protocol (tcp, udp, icmp, icmpv6, etc.)" << std::endl;
    std::cout << "  " << CYAN << "--port <port>" << RESET << "\t\t: Filter by source/destination port (1-65535)" << std::endl;

    std::cout << "Examples:" << std::endl;
    std::cout << "  ./sniffer eth0" << std::endl;
    std::cout << "  ./sniffer eth0 -p tcp" << std::endl;
    std::cout << "  ./sniffer eth0 --port 53 -p udp" << std::endl;  
    std::cout << "  ./sniffer eth0 -p tcp --port 80" << std::endl;
}

bool packet_matches_filter(const Packet& packet, const Packet::FilterConfig& filter) {
    if (filter.protocol.has_value() && packet.ip_protocol != filter.protocol.value()) {
        return false;
    }
    if (filter.port.has_value()) {
        if (packet.ip_protocol == Packet::IpProtocol::TCP && packet.tcpHeader.srcPort != filter.port.value() && packet.tcpHeader.destPort != filter.port.value()) {
            return false;
        }
        if (packet.ip_protocol == Packet::IpProtocol::UDP && packet.udpHeader.srcPort != filter.port.value() && packet.udpHeader.destPort != filter.port.value()) {
            return false;
        }   
    }
    return true;
}

int main(int argc, char* argv[]){
    
    //wlp0s20f3
    std::string interface{};
    Packet::FilterConfig filter;

    if(argc <= 1){
        print_correct_cli_format();
        return 1;       
    }
    else{
        interface = argv[1];
        if(interface == "-h" || interface == "--help")
        {
            print_correct_cli_format();
            return 0;
        }
        
        for(int i = 2; i < argc; ++i)
        {   
            std::string current_arg = argv[i];
            if(current_arg == "-p" || current_arg == "--protocol")
            {
                if(i + 1 < argc)
                {
                    std::string protocol = argv[++i];
                    //Not using a switch here since switch(arg) arg needs to be intergral or ENUM type
                    if(protocol == "tcp")
                        filter.protocol = Packet::IpProtocol::TCP;
                    else if(protocol == "udp")
                        filter.protocol = Packet::IpProtocol::UDP;
                    else if(protocol == "icmp")
                        filter.protocol = Packet::IpProtocol::ICMP;
                    else if(protocol == "icmpv6")
                        filter.protocol = Packet::IpProtocol::ICMPv6;
                    else if(protocol == "ah")
                        filter.protocol = Packet::IpProtocol::AH;
                    else if(protocol == "no_next_header")
                        filter.protocol = Packet::IpProtocol::NO_NEXT_HEADER;
                    else if(protocol == "hop_by_hop")
                        filter.protocol = Packet::IpProtocol::HOP_BY_HOP;
                    else if(protocol == "routing")
                        filter.protocol = Packet::IpProtocol::ROUTING;
                    else if(protocol == "fragment")
                        filter.protocol = Packet::IpProtocol::FRAGMENT;
                    else if(protocol == "encapsulating_security_payload")
                        filter.protocol = Packet::IpProtocol::ENCAPSULATING_SECURITY_PAYLOAD;
                    else if(protocol == "destination_options")
                        filter.protocol = Packet::IpProtocol::DESTINATION_OPTIONS;
                    else{
                        std::cerr << "Unknown protocol: " << protocol << std::endl;
                        std::cout << "Supported protocols: tcp, udp, icmp, icmpv6, ah, no_next_header, hop_by_hop, routing, fragment, encapsulating_security_payload, destination_options" << std::endl; 
                        print_correct_cli_format();
                        return 1;
                    }
                }
                else
                {
                    std::cerr << "Missing protocol argument after -p" << std::endl;
                    print_correct_cli_format();
                    return 1;
                }
            }
            else if(current_arg == "--port")
            {
                if(i + 1 < argc)
                {
                    try
                    {
                        filter.port = std::stoi(argv[++i]);
                        if(filter.port.value() > 65535)
                        {   
                            std::cerr << "Port number must be between 0 and 65535" << std::endl;
                            print_correct_cli_format();
                            return 1;
                        }
                    }
                    catch(const std::exception& e)
                    {
                        std::cerr << e.what() << '\n';
                        std::cerr << "Invalid port number: " << argv[i] << std::endl;
                        print_correct_cli_format();
                        return 1;
                    }
                }
                else
                {
                    std::cerr << "Missing port argument after --port" << std::endl;
                    print_correct_cli_format();
                    return 1;
                }
            }
            else{
                std::cerr << "Invalid argument: " << current_arg << std::endl;
                print_correct_cli_format();
                return 1;
            }
        }
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

                    if(packet_matches_filter(packet,filter)) PacketPrinter::print_packet(packet);
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