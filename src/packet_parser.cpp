#include "packet_parser.hpp"

#define VALID_ETHER_LEN 14
#define VALID_IPV4_LEN 20
#define VALID_IPV6_LEN 40
#define VALID_TCP_LEN 20
#define VALID_UDP_LEN 8
#define VALID_ICMP_LEN 4

//FOCUS ON FIXING IPV6 PARSING AS EXTENSION HEADERS MAKE IT A BIT TOUGHER THAN IMAGINED

Packet PacketParser::parse_packet(const std::vector<char>& data, size_t length) {
    Packet packet;

    if (length < VALID_ETHER_LEN) {
        throw std::runtime_error("Packet too short to contain Ethernet header");
    }

    parse_ether_header(data, length, packet);

    switch (packet.ethFrame.ethertype) {
        case Packet::EtherType::IPv4:
            if (length >= VALID_ETHER_LEN + VALID_IPV4_LEN) {
                parse_ipv4(data, length, packet);
            }
            break;

        case Packet::EtherType::IPv6:
            if (length >= VALID_ETHER_LEN + VALID_IPV6_LEN) {
                parse_ipv6(data, length, packet);
            }
            break;

        default:
            std::cerr << "Unsupported or unhandled EtherType: "
                      << std::hex << static_cast<uint16_t>(packet.ethFrame.ethertype)
                      << std::endl;
            break;
    }
    
    switch(packet.ip_protocol){
        case Packet::IpProtocol::TCP:
            parse_tcp(data, length, packet);
            break;
        case Packet::IpProtocol::UDP:
            parse_udp(data, length, packet);
            break;
        case Packet::IpProtocol::ICMP:
            parse_icmpv4(data, length, packet);
            break;
        case Packet::IpProtocol::ICMPv6:
            parse_icmpv6(data, length, packet);
            break;
        default:
            std::cerr << "Unsupported or unhandled IP Protocol: " << static_cast<uint8_t>(packet.ip_protocol) << std::endl;
            break;
    }

    return packet;
}

void PacketParser::parse_ether_header(const std::vector<char>& data, size_t length, Packet& packet) {
    if (length < VALID_ETHER_LEN) {
        throw std::runtime_error("Invalid Ethernet frame length");
    }

    // Copy MAC addresses (6 bytes each)
    std::copy(data.begin(), data.begin() + 6, packet.ethFrame.dest_mac.begin());
    std::copy(data.begin() + 6, data.begin() + 12, packet.ethFrame.src_mac.begin());

    // Extract EtherType (big-endian to host byte order)
    //big-endian so MSB at the first, bitwise operations over stoi as the data is not a string rather its byte array
    //so its more robust to use bitwise operations to make sure the data is in the correct format (network order)
    //static cast works directly without using stoi as it is binary data instead of a normal string
    uint16_t etherType = (static_cast<uint8_t>(data[12]) << 8) | static_cast<uint8_t>(data[13]);
    assign_ether_type(etherType, packet.ethFrame.ethertype);
}

void PacketParser::parse_ipv4(const std::vector<char>& data, size_t length, Packet& packet) {
    size_t ipv4_offset = VALID_ETHER_LEN;

    if (length < ipv4_offset + VALID_IPV4_LEN) {
        throw std::runtime_error("Invalid IPv4 packet length");
    }

    const char* ipv4_ptr = data.data() + ipv4_offset;

    packet.ipv4Header.version_ihl     = static_cast<uint8_t>(ipv4_ptr[0]);
    packet.ipv4Header.tos             = static_cast<uint8_t>(ipv4_ptr[1]);
    packet.ipv4Header.total_length    = (ipv4_ptr[2] << 8) | ipv4_ptr[3];
    packet.ipv4Header.identification  = (ipv4_ptr[4] << 8) | ipv4_ptr[5];
    packet.ipv4Header.flags_fragment  = (ipv4_ptr[6] << 8) | ipv4_ptr[7];
    packet.ipv4Header.ttl             = static_cast<uint8_t>(ipv4_ptr[8]);
    packet.ipv4Header.protocol        = static_cast<uint8_t>(ipv4_ptr[9]);
    packet.ipv4Header.header_checksum = (ipv4_ptr[10] << 8) | ipv4_ptr[11];

    std::copy(ipv4_ptr + 12, ipv4_ptr + 16, reinterpret_cast<char*>(&packet.ipv4Header.src_ip));
    std::copy(ipv4_ptr + 16, ipv4_ptr + 20, reinterpret_cast<char*>(&packet.ipv4Header.dest_ip));

    packet.OriginalIpHeader = packet.ipv4Header;
    packet.ip_protocol = get_ip_protocol(packet.ipv4Header.protocol);
    
    std::cout << "Detected Protocol: " << static_cast<uint8_t>(packet.ip_protocol) << std::endl;
}

void PacketParser::parse_ipv6(const std::vector<char>& data, size_t length, Packet& packet) {
    size_t ipv6_offset = VALID_ETHER_LEN;

    if (length < ipv6_offset + VALID_IPV6_LEN) {
        throw std::runtime_error("Invalid IPv6 packet length");
    }

    const char* ipv6_ptr = data.data() + ipv6_offset;

    packet.ipv6Header.version         = (ipv6_ptr[0] >> 4) & 0x0F;
    packet.ipv6Header.traffic_class   = ((ipv6_ptr[0] & 0x0F) << 4) | ((ipv6_ptr[1] >> 4) & 0x0F);
    packet.ipv6Header.flow_label      = ((ipv6_ptr[1] & 0x0F) << 16) | (ipv6_ptr[2] << 8) | ipv6_ptr[3];
    packet.ipv6Header.payload_length  = (ipv6_ptr[4] << 8) | ipv6_ptr[5];
    packet.ipv6Header.next_header     = static_cast<uint8_t>(ipv6_ptr[6]);
    packet.ipv6Header.hop_limit       = static_cast<uint8_t>(ipv6_ptr[7]);

    std::copy(ipv6_ptr + 8, ipv6_ptr + 24, packet.ipv6Header.src_ip.begin());
    std::copy(ipv6_ptr + 24, ipv6_ptr + 40, packet.ipv6Header.des_ip.begin());
    
    packet.OriginalIpHeader = packet.ipv6Header;
    packet.ip_protocol = get_ip_protocol(packet.ipv6Header.next_header);

    std::cout << "Detected Protocol: " << static_cast<uint8_t>(packet.ip_protocol) << std::endl;
}

void PacketParser::parse_tcp(const std::vector<char>& data, size_t length, Packet& packet)
{
    size_t tcp_offset = (packet.ethFrame.ethertype == Packet::EtherType::IPv4) ? VALID_ETHER_LEN + VALID_IPV4_LEN : VALID_ETHER_LEN + VALID_IPV6_LEN;

    if(length < tcp_offset + VALID_TCP_LEN)
    {
        throw std::runtime_error("Invalid TCP packet length");
    }

    const char* tcp_ptr = data.data() + tcp_offset;

    packet.tcpHeader.srcPort = (tcp_ptr[0] << 8) | tcp_ptr[1];
    packet.tcpHeader.destPort = (tcp_ptr[2] << 8) | tcp_ptr[3];
    packet.tcpHeader.seqNum = (tcp_ptr[4] << 24) | (tcp_ptr[5] << 16) | (tcp_ptr[6] << 8) | tcp_ptr[7];
    packet.tcpHeader.ackNum = (tcp_ptr[8] << 24) | (tcp_ptr[9] << 16) | (tcp_ptr[10] << 8) | tcp_ptr[11];
    packet.tcpHeader.dataOffset = (tcp_ptr[12] >> 4) & 0x0F;
    packet.tcpHeader.flags = tcp_ptr[13];
    packet.tcpHeader.windowSize = (tcp_ptr[14] << 8) | tcp_ptr[15];
    packet.tcpHeader.checksum = (tcp_ptr[16] << 8) | tcp_ptr[17];
    packet.tcpHeader.urgentPointer = (tcp_ptr[18] << 8) | tcp_ptr[19];


    
}

void PacketParser::parse_udp(const std::vector<char>& data, size_t length, Packet& packet){
    size_t udp_offset = (packet.ethFrame.ethertype == Packet::EtherType::IPv4) ? VALID_ETHER_LEN + VALID_IPV4_LEN : VALID_ETHER_LEN + VALID_IPV6_LEN;

    if(length < udp_offset + VALID_UDP_LEN)
    {
        throw std::runtime_error("Invalid UDP packet length");
    }

    const char* udp_ptr = data.data() + udp_offset;

    packet.udpHeader.srcPort = (udp_ptr[0] << 8) | udp_ptr[1];
    packet.udpHeader.destPort = (udp_ptr[2] << 8) | udp_ptr[3];
    packet.udpHeader.length = (udp_ptr[4] << 8) | udp_ptr[5];
    packet.udpHeader.checksum = (udp_ptr[6] << 8) | udp_ptr[7];
}


void PacketParser::parse_icmpv4(const std::vector<char>& data, size_t length, Packet& packet)
{
    size_t icmp_offset = VALID_ETHER_LEN + VALID_IPV4_LEN;

    if(length < icmp_offset + VALID_ICMP_LEN)
    {
        throw std::runtime_error("Invalid ICMP packet length");
    }

    const char* icmp_ptr = data.data() + icmp_offset;
    packet.icmpHeader.type = static_cast<uint8_t>(icmp_ptr[0]);
    packet.icmpHeader.code = static_cast<uint8_t>(icmp_ptr[1]);
    packet.icmpHeader.checksum = static_cast<uint16_t>((icmp_ptr[2] << 8) | icmp_ptr[3]);

    switch(packet.icmpHeader.type)
    {
        case 0:
        case 8:
        {
            Packet::ICMPEcho echo = {
                .identifier = static_cast<uint16_t>((icmp_ptr[4] << 8) | icmp_ptr[5]),
                .sequenceNumber = static_cast<uint16_t>((icmp_ptr[6] << 8) | icmp_ptr[7])
            };
            packet.icmpHeader.icmpData = echo;
            break;
        }
        case 3:
        {
            Packet::ICMPDestinationUnreachable dest = {
                .unused = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .OriginalIpHeader = packet.OriginalIpHeader,
            };
            packet.icmpHeader.icmpData = dest;
            break;
        }
        case 5:
        {
            Packet::ICMPRedirect redirect = {
                .gatewayAddress = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .OriginalIpHeader = packet.OriginalIpHeader,
            };
            packet.icmpHeader.icmpData = redirect;
            break;
        }
        case 11:
        {
            Packet::ICMPTimeExceeded timeExc = {
                .unused = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .OriginalIpHeader = packet.OriginalIpHeader,
            };
            packet.icmpHeader.icmpData = timeExc;
            break;
        }
        case 13:
        case 14:
        {
            Packet::ICMPTimestamp timest = {
                .identifier = (icmp_ptr[4] << 8) | icmp_ptr[5],
                .sequenceNumber = (icmp_ptr[6] << 8) | icmp_ptr[7],
                .originateTimestamp = (icmp_ptr[8] << 24) | (icmp_ptr[9] << 16) | (icmp_ptr[10] << 8) | icmp_ptr[11],
                .receiveTimestamp = (icmp_ptr[12] << 24) | (icmp_ptr[13] << 16) | (icmp_ptr[14] << 8) | icmp_ptr[15],
                .transmitTimestamp = (icmp_ptr[16] << 24) | (icmp_ptr[17] << 16) | (icmp_ptr[18] << 8) | icmp_ptr[19]
            };
            packet.icmpHeader.icmpData = timest;
            break;
        }
        case 17:
        case 18:
        {
            Packet::ICMPAddressMask addrMask = {
                .identifier = (icmp_ptr[4] << 8) | icmp_ptr[5],
                .sequenceNumber = (icmp_ptr[6] << 8) | icmp_ptr[7],
                .addressMask = (icmp_ptr[8] << 24) | (icmp_ptr[9] << 16) | (icmp_ptr[10] << 8) | icmp_ptr[11]
            };
            packet.icmpHeader.icmpData = addrMask;
            break;
        }
        default:
        {
            Packet::ICMPGeneric gen = {
                .rest_of_header = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .payload = std::vector<uint8_t>(icmp_ptr + 8, icmp_ptr + length),
            };
            //Moving prevents unneeded copies as std::vector<> is a big object
            packet.icmpHeader.icmpData = std::move(gen);
            std::cerr << "Unsupported or unhandled ICMP type: " << static_cast<uint16_t>(packet.icmpHeader.type) << std::endl;
            break;
        }
    }
}   

void PacketParser::parse_icmpv6(const std::vector<char>& data, size_t length, Packet& packet)
{
    size_t icmp_offset = VALID_ETHER_LEN + VALID_IPV6_LEN;
    
    if(length < icmp_offset + VALID_ICMP_LEN)
    {
        throw std::runtime_error("Invalid ICMP packet length");
    }

    const char* icmp_ptr = data.data() + icmp_offset; 

    packet.icmpHeader.type = static_cast<uint8_t>(icmp_ptr[0]);
    packet.icmpHeader.code = static_cast<uint8_t>(icmp_ptr[1]);
    packet.icmpHeader.checksum = static_cast<uint16_t>((icmp_ptr[2] << 8) | icmp_ptr[3]);

    switch(packet.icmpHeader.type)
    {
        case 128:
        case 129:
        {
            Packet::ICMPv6Echo echo = {
                .id = (icmp_ptr[4] << 8) | icmp_ptr[5],
                .sequence_num = (icmp_ptr[6] << 8) | icmp_ptr[7]
            };
            packet.icmpHeader.icmpData = echo;
            break;
        }
        case 1:
        {
            Packet::ICMPv6DestUnreachable dest = {
                .unused = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .payload = std::vector<uint8_t>(icmp_ptr + 8, icmp_ptr + length)
            };
            packet.icmpHeader.icmpData = dest;
            break;
        }
        case 2:
        {
            Packet::ICMPv6PacketTooBig tooBig = {
                .mtu = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .payload = std::vector<uint8_t>(icmp_ptr + 8, icmp_ptr + length)
            };
            packet.icmpHeader.icmpData = tooBig;
            break;
        }
        case 3:
        {
            Packet::ICMPv6TimeExceeded timeExc = {
                .unused = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .payload = std::vector<uint8_t>(icmp_ptr + 8, icmp_ptr + length)
            };
            packet.icmpHeader.icmpData = timeExc;
            break;
        }
        case 4:
        {
            Packet::ICMPv6ParamProblem paramProb = {
                .pointer = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .payload = std::vector<uint8_t>(icmp_ptr + 8, icmp_ptr + length)
            };
            packet.icmpHeader.icmpData = paramProb;
            break;
        }
        case 133:
        {
            Packet::ICMPv6RouterSolicit routerSolicit = {
                .reserved = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7]
            };
            packet.icmpHeader.icmpData = routerSolicit;
            break;
        }
        case 134:
        {
            Packet::ICMPv6RouterAdvert routerAdv = {
                .hop_limit = static_cast<uint8_t>(icmp_ptr[4]),
                .flags = static_cast<uint8_t>(icmp_ptr[5]),
                .router_lifetime = (icmp_ptr[6] << 8) | icmp_ptr[7],
                .reachable_time = (icmp_ptr[8] << 24) | (icmp_ptr[9] << 16) | (icmp_ptr[10] << 8) | icmp_ptr[11],
                .retransmit_time = (icmp_ptr[12] << 24) | (icmp_ptr[13] << 16) | (icmp_ptr[14] << 8) | icmp_ptr[15]
            };
            packet.icmpHeader.icmpData = routerAdv;
            break;
        }
        case 135:
        {
            Packet::ICMPv6NeighborSolicit neighborSolicit = {
                .reserved = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7]
            };
            std::copy(icmp_ptr + 8, icmp_ptr + 24, neighborSolicit.target_addr.begin());
            packet.icmpHeader.icmpData = neighborSolicit;
            break;
        }
        case 136:
        {
            Packet::ICMPv6NeighborAdvert neighborAdv = {
                .flags = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7]
            };
            std::copy(icmp_ptr + 8, icmp_ptr + 24, neighborAdv.target_addr.begin());
            packet.icmpHeader.icmpData = neighborAdv;
            break;
        }
        default:
        {
            Packet::ICMPGeneric gen = {
                .rest_of_header = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .payload = std::vector<uint8_t>(icmp_ptr + 8, icmp_ptr + length)
            };
            packet.icmpHeader.icmpData = gen;
            std::cerr << "Unsupported or unhandled ICMPv6 type: " << static_cast<uint16_t>(packet.icmpHeader.type) << std::endl;
            break;
        }
    }
}

Packet::IpProtocol PacketParser::get_ip_protocol(const uint8_t protocol)
{
    switch(protocol)
    {
        case 1: return Packet::IpProtocol::ICMP;
        case 6: return Packet::IpProtocol::TCP;
        case 17: return Packet::IpProtocol::UDP;
        case 58: return Packet::IpProtocol::ICMPv6;
        case 51: return Packet::IpProtocol::AH;
        case 59: return Packet::IpProtocol::NO_NEXT_HEADER;
        default: return Packet::IpProtocol::UNKNOWN;
    }
}

void PacketParser::assign_ether_type(uint16_t type, Packet::EtherType& etherType) {
    switch (type) {
        case 0x0800: etherType = Packet::EtherType::IPv4; break;
        case 0x86DD: etherType = Packet::EtherType::IPv6; break;
        case 0x0806: etherType = Packet::EtherType::ARP;  break;
        case 0x8100: etherType = Packet::EtherType::VLAN; break;
        case 0x8035: etherType = Packet::EtherType::RARP; break;
        default: 
            std::cerr << "Warning: Unknown EtherType: 0x" << std::hex << type << std::endl;
            etherType = Packet::EtherType::UNKNOWN;
            break;
    }
}
