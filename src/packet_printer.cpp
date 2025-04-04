#include "packet_printer.hpp"

void PacketPrinter::print_packet(const Packet& packet)
{   
    std::cout << LABEL << "\t\t\t[Packet Captured]" << RESET << std::endl;
    print_ethernet(packet);
    
    switch(packet.ethFrame.ethertype)
    {
        case Packet::EtherType::IPv4:
            print_ipv4(packet);
            print_transport_layer(packet);
            break;
        case Packet::EtherType::IPv6:
            print_ipv6(packet);
            print_transport_layer(packet);
            break;
        case Packet::EtherType::ARP:
            std::cout << LABEL << "ARP Frame" << RESET << std::endl;
            break;
        default:
            std::cout << LABEL << "Unknown EtherType" << RESET << std::endl;
            break;
    }   

    std::cout << LABEL << "----------------------------------------------------------" << RESET << std::endl;
    std::cout << LABEL << "----------------------------------------------------------" << RESET << std::endl;
    std::cout << LABEL << "----------------------------------------------------------" << RESET << std::endl;
}

void PacketPrinter::print_transport_layer(const Packet& packet)
{

    switch(packet.ip_protocol)
    {
        case Packet::IpProtocol::TCP:
            print_tcp(packet);
            break;
        case Packet::IpProtocol::UDP:
            print_udp(packet);
            break;
        case Packet::IpProtocol::ICMP:
            print_icmp(packet);
            break;
        case Packet::IpProtocol::ICMPv6:
            print_icmp(packet);
            break;
        default:
            std::cout << LABEL << "Unknown IP Protocol" << RESET << std::endl;
            break;
    }
}

void PacketPrinter::print_ethernet(const Packet& packet)
{
    std::string DesMACaddrString = packet.get_mac_string(packet.ethFrame.dest_mac);
    std::string SrcMACaddrString = packet.get_mac_string(packet.ethFrame.src_mac);
    std::string EthTypeStr = ether_type_to_string(packet);

    std::cout << LABEL << "Ethernet Frame:\n" << RESET << std::endl;
    std::cout << COLOR_MAC << "Des MAC Address: " << RESET << DesMACaddrString << '\n';
    std::cout << COLOR_MAC << "Src MAC Address: " << RESET << SrcMACaddrString << '\n';
    std::cout << COLOR_MAC << "EtherType: " << RESET << EthTypeStr << '\n';
    std::cout << LABEL << "Payload Length: " << RESET << packet.payloadLength << " bytes" << std::endl;
    print_separator();
}

std::string PacketPrinter::ether_type_to_string(const Packet& packet)
{
    switch(packet.ethFrame.ethertype)
    {
        case Packet::EtherType::IPv4:
            return "IPv4";
        case Packet::EtherType::IPv6:
            return "IPv6";
        case Packet::EtherType::ARP:
            return "ARP";
        default:
            return "Unknown";
    }
}



void PacketPrinter::print_ipv4(const Packet& packet)
{
    std::string srcIP = packet.get_ipv4_string(packet.ipv4Header.src_ip);
    std::string destIP = packet.get_ipv4_string(packet.ipv4Header.dest_ip);
    std::string ipProtocolStr = ip_protocol_to_string(packet);
    uint8_t version = packet.ipv4Header.version_ihl >> 4;
    uint8_t ihl = packet.ipv4Header.version_ihl & 0x0F;
    uint8_t tos = packet.ipv4Header.tos;
    uint16_t total_length = ntohs(packet.ipv4Header.total_length);
    uint16_t identification = ntohs(packet.ipv4Header.identification);
    uint16_t flags_fragment = ntohs(packet.ipv4Header.flags_fragment);
    uint8_t ttl = packet.ipv4Header.ttl;
    uint16_t header_checksum = ntohs(packet.ipv4Header.header_checksum);

    std::cout << LABEL << "IPv4 Header:\n" << RESET << std::endl;
    std::cout << COLOR_IPV4 << "Source IP: " << RESET << srcIP << '\n';
    std::cout << COLOR_IPV4 << "Destination IP: " << RESET << destIP << '\n';
    std::cout << COLOR_IPV4 << "Protocol: " << RESET << ipProtocolStr << '\n';
    std::cout << COLOR_IPV4 << "Version: " << RESET << static_cast<int>(version) << '\n';
    std::cout << COLOR_IPV4 << "IHL: " << RESET << static_cast<int>(ihl) << '\n';
    std::cout << COLOR_IPV4 << "TOS: " << RESET << static_cast<int>(tos) << '\n';
    std::cout << COLOR_IPV4 << "Total Length: " << RESET << total_length << '\n';
    std::cout << COLOR_IPV4 << "Identification: " << RESET << identification << '\n';
    std::cout << COLOR_IPV4 << "Flags and Fragment Offset: " << RESET << flags_fragment << '\n';
    std::cout << COLOR_IPV4 << "TTL: " << RESET << static_cast<int>(ttl) << '\n';
    std::cout << COLOR_IPV4 << "Header Checksum: " << RESET << header_checksum << '\n';
        
    print_separator();
}

void PacketPrinter::print_ipv6(const Packet& packet)
{
    std::string srcIP = packet.get_ipv6_string(packet.ipv6Header.src_ip);
    std::string destIP = packet.get_ipv6_string(packet.ipv6Header.des_ip);
    std::string ipProtocolStr = ip_protocol_to_string(packet);
    uint8_t version = packet.ipv6Header.version;
    uint8_t traffic_class = packet.ipv6Header.traffic_class;
    uint32_t flow_label = ntohl(packet.ipv6Header.flow_label);
    uint16_t payload_length = ntohs(packet.ipv6Header.payload_length);
    uint8_t next_header = packet.ipv6Header.next_header;
    uint8_t hop_limit = packet.ipv6Header.hop_limit;

    std::cout << LABEL << "IPv6 Header:\n" << RESET << std::endl;
    std::cout << COLOR_IPV6 << "Source IP: " << RESET << srcIP << '\n';
    std::cout << COLOR_IPV6 << "Destination IP: " << RESET << destIP << '\n';
    std::cout << COLOR_IPV6 << "Protocol: " << RESET << ipProtocolStr << '\n';
    std::cout << COLOR_IPV6 << "Version: " << RESET << static_cast<int>(version) << '\n';
    std::cout << COLOR_IPV6 << "Traffic Class: " << RESET << static_cast<int>(traffic_class) << '\n';
    std::cout << COLOR_IPV6 << "Flow Label: " << RESET << flow_label << '\n';
    std::cout << COLOR_IPV6 << "Payload Length: " << RESET << payload_length << '\n';
    std::cout << COLOR_IPV6 << "Next Header: " << RESET << next_header << '\n';
    std::cout << COLOR_IPV6 << "Hop Limit: " << RESET << static_cast<int>(hop_limit) << '\n';
    
    print_separator();
}

void PacketPrinter::print_udp(const Packet& packet)
{
    std::string srcPort = std::to_string(ntohs(packet.udpHeader.srcPort));
    std::string destPort = std::to_string(ntohs(packet.udpHeader.destPort));
    uint16_t length = ntohs(packet.udpHeader.length);
    uint16_t checksum = ntohs(packet.udpHeader.checksum);

    std::cout << LABEL << "UDP Header:\n" << RESET << std::endl;
    std::cout << COLOR_UDP << "Source Port: " << RESET << srcPort << '\n';
    std::cout << COLOR_UDP << "Destination Port: " << RESET << destPort << '\n';
    std::cout << COLOR_UDP << "Length: " << RESET  << length  << '\n';
    std::cout << COLOR_UDP << "Checksum: " << RESET  << checksum  << '\n';

    print_separator();
}

void PacketPrinter::print_icmp(const Packet& packet)
{
    std::string icmpTypeStr;
    uint8_t type = packet.icmpHeader.type;
    uint8_t code = packet.icmpHeader.code;
    uint16_t checksum = ntohs(packet.icmpHeader.checksum);

    if (std::holds_alternative<Packet::ICMPEcho>(packet.icmpHeader.icmpData)) {
        const auto& echo = std::get<Packet::ICMPEcho>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Echo Request/Reply";
        std::cout << COLOR_ICMP << "Identifier: " << RESET << echo.identifier << '\n';
        std::cout << COLOR_ICMP << "Sequence Number: " << RESET << echo.sequenceNumber << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPDestinationUnreachable>(packet.icmpHeader.icmpData)) {
        const auto& destUnreachable = std::get<Packet::ICMPDestinationUnreachable>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Destination Unreachable";
        std::cout << COLOR_ICMP << "Unused: " << RESET << destUnreachable.unused << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPTimeExceeded>(packet.icmpHeader.icmpData)) {
        const auto& timeExceeded = std::get<Packet::ICMPTimeExceeded>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Time Exceeded";
        std::cout << COLOR_ICMP << "Unused: " << RESET << timeExceeded.unused << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPRedirect>(packet.icmpHeader.icmpData)) {
        const auto& redirect = std::get<Packet::ICMPRedirect>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Redirect";
        std::cout << COLOR_ICMP << "Gateway Address: " << RESET << redirect.gatewayAddress << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPv6Echo>(packet.icmpHeader.icmpData)) {
        const auto& echo = std::get<Packet::ICMPv6Echo>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Echo Request/Reply (IPv6)";
        std::cout << COLOR_ICMP << "Identifier: " << RESET << echo.id << '\n';
        std::cout << COLOR_ICMP << "Sequence Number: " << RESET  << echo.sequence_num  << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPv6DestUnreachable>(packet.icmpHeader.icmpData)) {
        const auto& destUnreachable = std::get<Packet::ICMPv6DestUnreachable>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Destination Unreachable (IPv6)";
        std::cout << COLOR_ICMP << "Unused: " << RESET  << destUnreachable.unused  << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPv6TimeExceeded>(packet.icmpHeader.icmpData)) {
        const auto& timeExceeded = std::get<Packet::ICMPv6TimeExceeded>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Time Exceeded (IPv6)";
        std::cout << COLOR_ICMP << "Unused: " << RESET  << timeExceeded.unused  << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPv6ParamProblem>(packet.icmpHeader.icmpData)) {
        const auto& paramProblem = std::get<Packet::ICMPv6ParamProblem>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Parameter Problem (IPv6)";
        std::cout << COLOR_ICMP << "Pointer: " << RESET  << paramProblem.pointer  << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPv6RouterSolicit>(packet.icmpHeader.icmpData)) {
        const auto& routerSolicit = std::get<Packet::ICMPv6RouterSolicit>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Router Solicitation (IPv6)";
        std::cout << COLOR_ICMP << "Reserved: " << RESET  << routerSolicit.reserved  << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPv6RouterAdvert>(packet.icmpHeader.icmpData)) {
        const auto& routerAdvert = std::get<Packet::ICMPv6RouterAdvert>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Router Advertisement (IPv6)";
        std::cout << COLOR_ICMP << "Hop Limit: " << RESET  << static_cast<int>(routerAdvert.hop_limit)  << '\n';
        std::cout << COLOR_ICMP << "Flags: " << RESET  <<
            static_cast<int>(routerAdvert.flags)  << '\n';
        std::cout << COLOR_ICMP << "Router Lifetime: " << RESET  << routerAdvert.router_lifetime  << '\n';
        std::cout << COLOR_ICMP << "Reachable Time: " << RESET  << routerAdvert.reachable_time  << '\n';
        std::cout << COLOR_ICMP << "Retransmit Time: " << RESET  << routerAdvert.retransmit_time  << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPv6Generic>(packet.icmpHeader.icmpData)) {
        const auto& generic = std::get<Packet::ICMPv6Generic>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Generic ICMPv6";
        std::cout << COLOR_ICMP << "Rest: " << RESET  << generic.rest  << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPv6NeighborSolicit>(packet.icmpHeader.icmpData)) {
        const auto& neighborSolicit = std::get<Packet::ICMPv6NeighborSolicit>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Neighbor Solicitation (IPv6)";
        std::cout << COLOR_ICMP << "Reserved: " << RESET  << neighborSolicit.reserved  << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPv6NeighborAdvert>(packet.icmpHeader.icmpData)) {
        const auto& neighborAdvert = std::get<Packet::ICMPv6NeighborAdvert>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Neighbor Advertisement (IPv6)";
        std::cout << COLOR_ICMP << "Flags: " << RESET  << neighborAdvert.flags  << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPv6TimeExceeded>(packet.icmpHeader.icmpData)) {
        const auto& timeExceeded = std::get<Packet::ICMPv6TimeExceeded>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Time Exceeded (IPv6)";
        std::cout << COLOR_ICMP << "Unused: " << RESET  << timeExceeded.unused  << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPv6PacketTooBig>(packet.icmpHeader.icmpData)) {
        const auto& packetTooBig = std::get<Packet::ICMPv6PacketTooBig>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Packet Too Big (IPv6)";
        std::cout << COLOR_ICMP << "MTU: " << RESET  << packetTooBig.mtu  << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPAddressMask>(packet.icmpHeader.icmpData)) {
        const auto& addressMask = std::get<Packet::ICMPAddressMask>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Address Mask";
        std::cout << COLOR_ICMP << "Identifier: " << RESET  << addressMask.identifier  << '\n';
        std::cout << COLOR_ICMP << "Sequence Number: " << RESET  << addressMask.sequenceNumber  << '\n';
        std::cout << COLOR_ICMP << "Address Mask: " << RESET  << addressMask.addressMask  << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPGeneric>(packet.icmpHeader.icmpData)) {
        const auto& generic = std::get<Packet::ICMPGeneric>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Generic ICMP";
        std::cout << COLOR_ICMP << "Rest of Header: " << RESET  << generic.rest_of_header  << '\n';
    }
    else if(std::holds_alternative<Packet::ICMPTimestamp>(packet.icmpHeader.icmpData))
    {
        const auto& icmpTimeStamp = std::get<Packet::ICMPTimestamp>(packet.icmpHeader.icmpData);
        icmpTypeStr = "ICMP Timestamp";
        std::cout << COLOR_ICMP << "Identifier: " << RESET  << icmpTimeStamp.identifier  << '\n';
        std::cout << COLOR_ICMP << "Sequence Number: " << RESET  << icmpTimeStamp.sequenceNumber  << '\n';
        std::cout << COLOR_ICMP << "Originate Timestamp: " << RESET  << icmpTimeStamp.originateTimestamp  << '\n';
        std::cout << COLOR_ICMP << "Receive Timestamp: " << RESET  << icmpTimeStamp.receiveTimestamp  << '\n';
        std::cout << COLOR_ICMP << "Transmit Timestamp: " << RESET << icmpTimeStamp.transmitTimestamp << '\n';
    }
    else {
        icmpTypeStr = "Unknown ICMP Type";
    }

    std::cout << LABEL << "ICMP Header:\n" << RESET << std::endl;
    std::cout << COLOR_ICMP << "Type: " << RESET << static_cast<int>(type) << '\n';
    std::cout << COLOR_ICMP << "Code: " << RESET << static_cast<int>(code) << '\n';
    std::cout << COLOR_ICMP << "Checksum: " << RESET  << checksum  << '\n';
    std::cout << COLOR_ICMP << "ICMP Type: "  << RESET  << icmpTypeStr  << '\n';

    print_separator();
}

void PacketPrinter::print_tcp(const Packet& packet)
{
    std::string srcPort = std::to_string(ntohs(packet.tcpHeader.srcPort));
    std::string destPort = std::to_string(ntohs(packet.tcpHeader.destPort));
    uint32_t seqNum = ntohl(packet.tcpHeader.seqNum);
    uint32_t ackNum = ntohl(packet.tcpHeader.ackNum);
    uint8_t dataOffset = packet.tcpHeader.dataOffset;
    uint8_t flags = packet.tcpHeader.flags;
    uint16_t windowSize = ntohs(packet.tcpHeader.windowSize);
    uint16_t checksum = ntohs(packet.tcpHeader.checksum);
    uint16_t urgentPointer = ntohs(packet.tcpHeader.urgentPointer);

    std::cout << LABEL << "TCP Header:\n" << RESET << std::endl;
    std::cout << COLOR_TCP << "Source Port: " << RESET << srcPort << '\n';
    std::cout << COLOR_TCP << "Destination Port: " << RESET << destPort << '\n';
    std::cout << COLOR_TCP << "Sequence Number: " << RESET << seqNum << '\n';
    std::cout << COLOR_TCP << "Acknowledgment Number: " << RESET << ackNum << '\n';
    std::cout << COLOR_TCP << "Data Offset: " << RESET << static_cast<int>(dataOffset) << '\n';
    std::cout << COLOR_TCP << "Flags: " << RESET << static_cast<int>(flags) << '\n';
    std::cout << COLOR_TCP << "Window Size: " << RESET << windowSize << '\n';
    std::cout << COLOR_TCP << "Checksum: " << RESET  << checksum << '\n';
    std::cout << LABEL <<  "Urgent Pointer: " << RESET  << urgentPointer << '\n';

    print_separator();

    if(packet.httpData.has_value())
    {
        print_http(packet);
    }
}

void PacketPrinter::print_http(const Packet& packet)
{
    const HttpParser::HTTPMessage& http_data = packet.httpData.value();

    std::cout << LABEL << "HTTP Info:\n" << RESET; 

    if (http_data.isRequest) {
        std::cout << COLOR_HTTP << "  Request:  " << RESET << http_data.method << " " << http_data.url << " " << http_data.version << '\n';
    } else {
        std::cout << COLOR_HTTP << "  Response: " << RESET << http_data.version << " " << http_data.statusCode << " " << http_data.statusText << '\n';
    }

    if (!http_data.headers.empty()) {
        std::cout << COLOR_HTTP << "  Headers: " << RESET << '\n';
        for(const auto& pair : http_data.headers)
        {
            std::cout << "    " << pair.first << ": " << pair.second << '\n';
        }
    }

    if (!http_data.body.empty()) {
        std::cout << COLOR_HTTP << "  Body Length: " << RESET << http_data.body.size() << '\n';
        std::cout << COLOR_HTTP << "  Body (ASCII, # = non-printable): " << RESET; 
        int chars_on_line = 0;
        const int MAX_CHARS_PER_LINE = 80; 

        for(char c : http_data.body)
        {
            if(isprint(static_cast<unsigned char>(c))) 
            {
                std::cout << c;
            }
            else
            {
                std::cout << '#'; 
            }

            chars_on_line++;
            if (chars_on_line >= MAX_CHARS_PER_LINE) {
                std::cout << '\n'; 
                 std::cout << "    "; 
                chars_on_line = 0;
            }
        }
        std::cout << '\n'; 
    }
}

std::string PacketPrinter::ip_protocol_to_string(const Packet& packet)
{
    switch(packet.ip_protocol)
    {
        case Packet::IpProtocol::ICMP:
            return "ICMP";
        case Packet::IpProtocol::TCP:
            return "TCP";
        case Packet::IpProtocol::UDP:
            return "UDP";
        case Packet::IpProtocol::ICMPv6:
            return "ICMPv6";
        case Packet::IpProtocol::AH:
            return "AH";
        case Packet::IpProtocol::NO_NEXT_HEADER:
            return "No Next Header";
        case Packet::IpProtocol::HOP_BY_HOP:
            return "Hop-by-Hop";
        case Packet::IpProtocol::ROUTING:
            return "Routing";
        case Packet::IpProtocol::FRAGMENT:
            return "Fragment";
        case Packet::IpProtocol::ENCAPSULATING_SECURITY_PAYLOAD:
            return "Encapsulating Security Payload";
        case Packet::IpProtocol::DESTINATION_OPTIONS:
            return "Destination Options";
        default:
            return "Unknown";
    }
}


void PacketPrinter::print_separator(){
    std::cout << LABEL << "\n\n----------------------------------------------------------\n\n" << RESET << std::endl;
}