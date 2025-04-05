#include "packet_printer.hpp"
#include <iostream>
#include <iomanip>
#include <cctype>   // for isprint()

// No per-header separator is used now.
// Only two separators will be printed at the end of the entire packet output.

std::string PacketPrinter::ether_type_to_string(const Packet& packet) {
    switch (packet.ethFrame.ethertype) {
        case Packet::EtherType::IPv4: return "IPv4";
        case Packet::EtherType::IPv6: return "IPv6";
        case Packet::EtherType::ARP:  return "ARP";
        default:                      return "Unknown";
    }
}

std::string PacketPrinter::ip_protocol_to_string(const Packet& packet) {
    switch (packet.ip_protocol) {
        case Packet::IpProtocol::ICMP:  return "ICMP";
        case Packet::IpProtocol::TCP:   return "TCP";
        case Packet::IpProtocol::UDP:   return "UDP";
        case Packet::IpProtocol::ICMPv6:return "ICMPv6";
        case Packet::IpProtocol::AH:    return "AH";
        case Packet::IpProtocol::NO_NEXT_HEADER: return "No Next Header";
        case Packet::IpProtocol::HOP_BY_HOP:       return "Hop-by-Hop";
        case Packet::IpProtocol::ROUTING:          return "Routing";
        case Packet::IpProtocol::FRAGMENT:         return "Fragment";
        case Packet::IpProtocol::ENCAPSULATING_SECURITY_PAYLOAD: return "Encapsulating Security Payload";
        case Packet::IpProtocol::DESTINATION_OPTIONS: return "Destination Options";
        default: return "Unknown";
    }
}

void PacketPrinter::print_packet(const Packet& packet) {   
    // Packet captured header
    std::cout << LABEL << BOLD << "\t\t\t[ Packet Captured ]" 
              << RESET << std::endl << std::endl;
    
    print_ethernet(packet);

    switch (packet.ethFrame.ethertype) {
        case Packet::EtherType::IPv4:
            print_ipv4(packet);
            print_transport_layer(packet);
            break;
        case Packet::EtherType::IPv6:
            print_ipv6(packet);
            print_transport_layer(packet);
            break;
        case Packet::EtherType::ARP:
            std::cout << LABEL << BOLD << "ARP Frame" << RESET << std::endl;
            break;
        default:
            std::cout << LABEL << BOLD << "Unknown EtherType" << RESET << std::endl;
            break;
    }   

    // Print two back-to-back separators at the end of the packet
    std::cout << LABEL << "----------------------------------------------------------" 
              << RESET << std::endl;
    std::cout << LABEL << "----------------------------------------------------------" 
              << RESET << std::endl;
}

void PacketPrinter::print_transport_layer(const Packet& packet) {
    switch (packet.ip_protocol) {
        case Packet::IpProtocol::TCP:
            print_tcp(packet);
            break;
        case Packet::IpProtocol::UDP:
            print_udp(packet);
            break;
        case Packet::IpProtocol::ICMP:
        case Packet::IpProtocol::ICMPv6:
            print_icmp(packet);
            break;
        default:
            std::cout << LABEL << BOLD << "Unknown IP Protocol" << RESET << std::endl;
            break;
    }
}

void PacketPrinter::print_ethernet(const Packet& packet) {
    std::string desMAC = packet.get_mac_string(packet.ethFrame.dest_mac);
    std::string srcMAC = packet.get_mac_string(packet.ethFrame.src_mac);
    std::string ethTypeStr = ether_type_to_string(packet);

    std::cout << LABEL << BOLD << "Ethernet Frame:" << RESET << std::endl;
    std::cout << COLOR_MAC << BOLD << "  Des MAC Address: " << RESET << desMAC << std::endl;
    std::cout << COLOR_MAC << BOLD << "  Src MAC Address: " << RESET << srcMAC << std::endl;
    std::cout << COLOR_MAC << BOLD << "  EtherType      : " << RESET << ethTypeStr << std::endl;
    std::cout << LABEL << BOLD << "  Payload Length : " << RESET << packet.payloadLength 
              << " bytes" << std::endl << std::endl;
}

void PacketPrinter::print_ipv4(const Packet& packet) {
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

    std::cout << LABEL << BOLD << "IPv4 Header:" << RESET << std::endl;
    std::cout << COLOR_IPV4 << BOLD << "  Source IP           : " << RESET << srcIP << std::endl;
    std::cout << COLOR_IPV4 << BOLD << "  Destination IP      : " << RESET << destIP << std::endl;
    std::cout << COLOR_IPV4 << BOLD << "  Protocol            : " << RESET << ipProtocolStr << std::endl;
    std::cout << COLOR_IPV4 << BOLD << "  Version             : " << RESET << static_cast<int>(version) << std::endl;
    std::cout << COLOR_IPV4 << BOLD << "  IHL                 : " << RESET << static_cast<int>(ihl) << std::endl;
    std::cout << COLOR_IPV4 << BOLD << "  TOS                 : " << RESET << static_cast<int>(tos) << std::endl;
    std::cout << COLOR_IPV4 << BOLD << "  Total Length        : " << RESET << total_length << std::endl;
    std::cout << COLOR_IPV4 << BOLD << "  Identification      : " << RESET << identification << std::endl;
    std::cout << COLOR_IPV4 << BOLD << "  Flags/Fragment      : " << RESET << flags_fragment << std::endl;
    std::cout << COLOR_IPV4 << BOLD << "  TTL                 : " << RESET << static_cast<int>(ttl) << std::endl;
    std::cout << COLOR_IPV4 << BOLD << "  Header Checksum     : " << RESET << header_checksum << std::endl << std::endl;
}

void PacketPrinter::print_ipv6(const Packet& packet) {
    std::string srcIP = packet.get_ipv6_string(packet.ipv6Header.src_ip);
    std::string destIP = packet.get_ipv6_string(packet.ipv6Header.des_ip);
    std::string ipProtocolStr = ip_protocol_to_string(packet);
    uint8_t version = packet.ipv6Header.version;
    uint8_t traffic_class = packet.ipv6Header.traffic_class;
    uint32_t flow_label = ntohl(packet.ipv6Header.flow_label);
    uint16_t payload_length = ntohs(packet.ipv6Header.payload_length);
    uint8_t next_header = packet.ipv6Header.next_header;
    uint8_t hop_limit = packet.ipv6Header.hop_limit;

    std::cout << LABEL << BOLD << "IPv6 Header:" << RESET << std::endl;
    std::cout << COLOR_IPV6 << BOLD << "  Source IP      : " << RESET << srcIP << std::endl;
    std::cout << COLOR_IPV6 << BOLD << "  Destination IP : " << RESET << destIP << std::endl;
    std::cout << COLOR_IPV6 << BOLD << "  Protocol       : " << RESET << ipProtocolStr << std::endl;
    std::cout << COLOR_IPV6 << BOLD << "  Version        : " << RESET << static_cast<int>(version) << std::endl;
    std::cout << COLOR_IPV6 << BOLD << "  Traffic Class  : " << RESET << static_cast<int>(traffic_class) << std::endl;
    std::cout << COLOR_IPV6 << BOLD << "  Flow Label     : " << RESET << flow_label << std::endl;
    std::cout << COLOR_IPV6 << BOLD << "  Payload Length : " << RESET << payload_length << std::endl;
    std::cout << COLOR_IPV6 << BOLD << "  Next Header    : " << RESET << static_cast<int>(next_header) << std::endl;
    std::cout << COLOR_IPV6 << BOLD << "  Hop Limit      : " << RESET << static_cast<int>(hop_limit) << std::endl << std::endl;
}

void PacketPrinter::print_udp(const Packet& packet) {
    std::string srcPort = std::to_string(ntohs(packet.udpHeader.srcPort));
    std::string destPort = std::to_string(ntohs(packet.udpHeader.destPort));
    uint16_t length = ntohs(packet.udpHeader.length);
    uint16_t checksum = ntohs(packet.udpHeader.checksum);

    std::cout << LABEL << BOLD << "UDP Header:" << RESET << std::endl;
    std::cout << COLOR_UDP << BOLD << "  Source Port     : " << RESET << srcPort << std::endl;
    std::cout << COLOR_UDP << BOLD << "  Destination Port: " << RESET << destPort << std::endl;
    std::cout << COLOR_UDP << BOLD << "  Length          : " << RESET << length << std::endl;
    std::cout << COLOR_UDP << BOLD << "  Checksum        : " << RESET << checksum << std::endl << std::endl;
}

void PacketPrinter::print_icmp(const Packet& packet) {
    std::string icmpTypeStr;
    uint8_t type = packet.icmpHeader.type;
    uint8_t code = packet.icmpHeader.code;
    uint16_t checksum = ntohs(packet.icmpHeader.checksum);

    if (std::holds_alternative<Packet::ICMPEcho>(packet.icmpHeader.icmpData)) {
        const auto& echo = std::get<Packet::ICMPEcho>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Echo Request/Reply";
        std::cout << COLOR_ICMP << BOLD << "  Identifier      : " << RESET << echo.identifier << std::endl;
        std::cout << COLOR_ICMP << BOLD << "  Sequence Number : " << RESET << echo.sequenceNumber << std::endl;
    }
    else if (std::holds_alternative<Packet::ICMPDestinationUnreachable>(packet.icmpHeader.icmpData)) {
        const auto& destUnreachable = std::get<Packet::ICMPDestinationUnreachable>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Destination Unreachable";
        std::cout << COLOR_ICMP << BOLD << "  Unused          : " << RESET << destUnreachable.unused << std::endl;
    }
    else if (std::holds_alternative<Packet::ICMPTimeExceeded>(packet.icmpHeader.icmpData)) {
        const auto& timeExceeded = std::get<Packet::ICMPTimeExceeded>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Time Exceeded";
        std::cout << COLOR_ICMP << BOLD << "  Unused          : " << RESET << timeExceeded.unused << std::endl;
    }
    else if (std::holds_alternative<Packet::ICMPRedirect>(packet.icmpHeader.icmpData)) {
        const auto& redirect = std::get<Packet::ICMPRedirect>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Redirect";
        std::cout << COLOR_ICMP << BOLD << "  Gateway Address : " << RESET << redirect.gatewayAddress << std::endl;
    }
    else if (std::holds_alternative<Packet::ICMPv6Echo>(packet.icmpHeader.icmpData)) {
        const auto& echo = std::get<Packet::ICMPv6Echo>(packet.icmpHeader.icmpData);
        icmpTypeStr = "Echo Request/Reply (IPv6)";
        std::cout << COLOR_ICMP << BOLD << "  Identifier      : " << RESET << echo.id << std::endl;
        std::cout << COLOR_ICMP << BOLD << "  Sequence Number : " << RESET << echo.sequence_num << std::endl;
    }
    else if (std::holds_alternative<Packet::ICMPTimestamp>(packet.icmpHeader.icmpData)) {
        const auto& icmpTimeStamp = std::get<Packet::ICMPTimestamp>(packet.icmpHeader.icmpData);
        icmpTypeStr = "ICMP Timestamp";
        std::cout << COLOR_ICMP << BOLD << "  Identifier           : " << RESET << icmpTimeStamp.identifier << std::endl;
        std::cout << COLOR_ICMP << BOLD << "  Sequence Number      : " << RESET << icmpTimeStamp.sequenceNumber << std::endl;
        std::cout << COLOR_ICMP << BOLD << "  Originate Timestamp  : " << RESET << icmpTimeStamp.originateTimestamp << std::endl;
        std::cout << COLOR_ICMP << BOLD << "  Receive Timestamp    : " << RESET << icmpTimeStamp.receiveTimestamp << std::endl;
        std::cout << COLOR_ICMP << BOLD << "  Transmit Timestamp   : " << RESET << icmpTimeStamp.transmitTimestamp << std::endl;
    }
    else {
        icmpTypeStr = "Unknown ICMP Type";
    }

    std::cout << LABEL << BOLD << "ICMP Header:" << RESET << std::endl;
    std::cout << COLOR_ICMP << BOLD << "  Type      : " << RESET << static_cast<int>(type) << std::endl;
    std::cout << COLOR_ICMP << BOLD << "  Code      : " << RESET << static_cast<int>(code) << std::endl;
    std::cout << COLOR_ICMP << BOLD << "  Checksum  : " << RESET << checksum << std::endl;
    std::cout << COLOR_ICMP << BOLD << "  ICMP Type : " << RESET << icmpTypeStr << std::endl << std::endl;
}

void PacketPrinter::print_tcp(const Packet& packet) {
    std::string srcPort = std::to_string(ntohs(packet.tcpHeader.srcPort));
    std::string destPort = std::to_string(ntohs(packet.tcpHeader.destPort));
    uint32_t seqNum = ntohl(packet.tcpHeader.seqNum);
    uint32_t ackNum = ntohl(packet.tcpHeader.ackNum);
    uint8_t dataOffset = packet.tcpHeader.dataOffset;
    uint8_t flags = packet.tcpHeader.flags;
    uint16_t windowSize = ntohs(packet.tcpHeader.windowSize);
    uint16_t checksum = ntohs(packet.tcpHeader.checksum);
    uint16_t urgentPointer = ntohs(packet.tcpHeader.urgentPointer);

    std::cout << LABEL << BOLD << "TCP Header:" << RESET << std::endl;
    std::cout << COLOR_TCP << BOLD << "  Source Port         : " << RESET << srcPort << std::endl;
    std::cout << COLOR_TCP << BOLD << "  Destination Port    : " << RESET << destPort << std::endl;
    std::cout << COLOR_TCP << BOLD << "  Sequence Number     : " << RESET << seqNum << std::endl;
    std::cout << COLOR_TCP << BOLD << "  Acknowledgment Num  : " << RESET << ackNum << std::endl;
    std::cout << COLOR_TCP << BOLD << "  Data Offset         : " << RESET << static_cast<int>(dataOffset) << std::endl;
    std::cout << COLOR_TCP << BOLD << "  Flags               : " << RESET << static_cast<int>(flags) << std::endl;
    std::cout << COLOR_TCP << BOLD << "  Window Size         : " << RESET << windowSize << std::endl;
    std::cout << COLOR_TCP << BOLD << "  Checksum            : " << RESET << checksum << std::endl;
    std::cout << LABEL    << BOLD << "  Urgent Pointer      : " << RESET << urgentPointer << std::endl << std::endl;

    if (packet.httpData.has_value()) {
        print_http(packet);
    }
}

void PacketPrinter::print_http(const Packet& packet) {
    const HttpParser::HTTPMessage& http_data = packet.httpData.value();

    std::cout << LABEL << BOLD << "HTTP Info:" << RESET << std::endl;

    if (http_data.isRequest) {
        std::cout << COLOR_HTTP << BOLD << "  Request : " << RESET 
                  << http_data.method << " " << http_data.url << " " << http_data.version << std::endl;
    } else {
        std::cout << COLOR_HTTP << BOLD << "  Response: " << RESET 
                  << http_data.version << " " << http_data.statusCode << " " << http_data.statusText << std::endl;
    }

    if (!http_data.headers.empty()) {
        std::cout << COLOR_HTTP << BOLD << "  Headers : " << RESET << std::endl;
        for (const auto& pair : http_data.headers) {
            std::cout << "    " << pair.first << ": " << pair.second << std::endl;
        }
    }

    if (!http_data.body.empty()) {
        std::cout << COLOR_HTTP << BOLD << "  Body Length: " << RESET << http_data.body.size() << std::endl;
        std::cout << COLOR_HTTP << BOLD << "  Body (ASCII, # = non-printable): " << RESET;
        int chars_on_line = 0;
        const int MAX_CHARS_PER_LINE = 80;

        for (char c : http_data.body) {
            std::cout << (isprint(static_cast<unsigned char>(c)) ? c : '#');
            chars_on_line++;
            if (chars_on_line >= MAX_CHARS_PER_LINE) {
                std::cout << '\n' << "    ";
                chars_on_line = 0;
            }
        }
        std::cout << std::endl;
    }
}
