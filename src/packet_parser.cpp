#include "packet_parser.hpp"

#define VALID_ETHER_LEN 14
#define VALID_IPV4_LEN 20
#define VALID_IPV6_LEN 40
#define VALID_TCP_LEN 20
#define VALID_UDP_LEN 8
#define VALID_ICMP_LEN 4

Packet PacketParser::parse_packet(const std::vector<char>& data, size_t length) {
    Packet packet;

    // Ensure the packet is long enough to contain the Ethernet header
    if (length < VALID_ETHER_LEN) {
        throw std::runtime_error("Packet too short to contain Ethernet header");
    }

    // Parse the Ethernet header first
    parse_ether_header(data, length, packet);

    // Determine the type of Ethernet payload and parse accordingly
    switch (packet.ethFrame.ethertype) {
        case Packet::EtherType::IPv4:
            // Ensure the packet is long enough to contain the IPv4 header
            if (length >= VALID_ETHER_LEN + VALID_IPV4_LEN) {
                parse_ipv4(data, length, packet);
            }
            break;

        case Packet::EtherType::IPv6:
            // Ensure the packet is long enough to contain the IPv6 header
            if (length >= VALID_ETHER_LEN + VALID_IPV6_LEN) {
                parse_ipv6(data, length, packet);
            }
            break;

        default:
            // Log unsupported EtherType for debugging purposes
            std::cerr << "Unsupported or unhandled EtherType: "
                      << std::hex << static_cast<uint16_t>(packet.ethFrame.ethertype)
                      << std::endl;
            break;
    }

    // Determine the IP protocol and parse accordingly
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
            // Log unsupported IP protocol for debugging purposes
            std::cerr << "Unsupported or unhandled IP Protocol: " << static_cast<uint8_t>(packet.ip_protocol) << std::endl;
            break;
    }

    return packet;
}

void PacketParser::parse_ether_header(const std::vector<char>& data, size_t length, Packet& packet) {
    // Ensure the packet is long enough to contain the Ethernet header
    if (length < VALID_ETHER_LEN) {
        throw std::runtime_error("Invalid Ethernet frame length");
    }

    // Copy the destination and source MAC addresses (6 bytes each)
    std::copy(data.begin(), data.begin() + 6, packet.ethFrame.dest_mac.begin());
    std::copy(data.begin() + 6, data.begin() + 12, packet.ethFrame.src_mac.begin());

    // Extract the EtherType field (big-endian to host byte order)
    uint16_t etherType = (static_cast<uint8_t>(data[12]) << 8) | static_cast<uint8_t>(data[13]);
    assign_ether_type(etherType, packet.ethFrame.ethertype);
}

void PacketParser::parse_ipv4(const std::vector<char>& data, size_t length, Packet& packet) {
    size_t ipv4_offset = VALID_ETHER_LEN;

    // Ensure the packet is long enough to contain the IPv4 header
    if (length < ipv4_offset + VALID_IPV4_LEN) {
        throw std::runtime_error("Invalid IPv4 packet length");
    }

    const char* ipv4_ptr = data.data() + ipv4_offset;

    // Parse the IPv4 header fields
    packet.ipv4Header.version_ihl     = static_cast<uint8_t>(ipv4_ptr[0]);
    packet.ipv4Header.tos             = static_cast<uint8_t>(ipv4_ptr[1]);
    packet.ipv4Header.total_length    = (ipv4_ptr[2] << 8) | ipv4_ptr[3];
    packet.ipv4Header.identification  = (ipv4_ptr[4] << 8) | ipv4_ptr[5];
    packet.ipv4Header.flags_fragment  = (ipv4_ptr[6] << 8) | ipv4_ptr[7];
    packet.ipv4Header.ttl             = static_cast<uint8_t>(ipv4_ptr[8]);
    packet.ipv4Header.protocol        = static_cast<uint8_t>(ipv4_ptr[9]);
    packet.ipv4Header.header_checksum = (ipv4_ptr[10] << 8) | ipv4_ptr[11];

    // Copy the source and destination IP addresses
    std::copy(ipv4_ptr + 12, ipv4_ptr + 16, reinterpret_cast<char*>(&packet.ipv4Header.src_ip));
    std::copy(ipv4_ptr + 16, ipv4_ptr + 20, reinterpret_cast<char*>(&packet.ipv4Header.dest_ip));

    // Store the original IP header and determine the IP protocol
    packet.OriginalIpHeader = packet.ipv4Header;
    packet.ip_protocol = get_ip_protocol(packet.ipv4Header.protocol);

    std::cout << "Detected Protocol: " << static_cast<uint8_t>(packet.ip_protocol) << std::endl;
}

void PacketParser::parse_ipv6(const std::vector<char>& data, size_t length, Packet& packet) {
    size_t ipv6_offset = VALID_ETHER_LEN;

    // Ensure the packet is long enough to contain the IPv6 header
    if (length < ipv6_offset + VALID_IPV6_LEN) {
        throw std::runtime_error("Invalid IPv6 packet length");
    }

    const char* ipv6_ptr = data.data() + ipv6_offset;

    // Parse the IPv6 header fields
    packet.ipv6Header.version         = (ipv6_ptr[0] >> 4) & 0x0F;
    packet.ipv6Header.traffic_class   = ((ipv6_ptr[0] & 0x0F) << 4) | ((ipv6_ptr[1] >> 4) & 0x0F);
    packet.ipv6Header.flow_label      = ((ipv6_ptr[1] & 0x0F) << 16) | (ipv6_ptr[2] << 8) | ipv6_ptr[3];
    packet.ipv6Header.payload_length  = (ipv6_ptr[4] << 8) | ipv6_ptr[5];

    // Handle extension headers if present
    const char* copyOffset = ipv6_ptr + VALID_IPV6_LEN;
    uint8_t currHeader = static_cast<uint8_t>(ipv6_ptr[6]);
    size_t currLength = ipv6_offset + VALID_IPV6_LEN;
    size_t extension_count = 0;
    const size_t MAX_EXTENSIONS = 15; // Reasonable upper limit for extension headers

    // Traverse the linked list of extension headers
    while(is_extension_header(currHeader)) {
        if(++extension_count > MAX_EXTENSIONS) {
            throw std::runtime_error("Exceeded maximum number of IPv6 extension headers");
        }
        if(currLength + 8 > length) {
            throw std::runtime_error("Invalid IPv6 packet length during extension header parsing");
        }

        uint8_t header_ext_len = static_cast<uint8_t>(copyOffset[1]);
        currLength += (header_ext_len * 8) + 8;

        if(currLength > length) {
            throw std::runtime_error("Invalid IPv6 packet length after extension header parsing");
        }

        currHeader = static_cast<uint8_t>(copyOffset[0]);
        copyOffset += (header_ext_len * 8) + 8;
    }

    // Store the next header and hop limit fields
    packet.ipv6Header.next_header     = currHeader;
    packet.ipv6Header.hop_limit       = static_cast<uint8_t>(ipv6_ptr[7]);

    // Copy the source and destination IP addresses
    std::copy(ipv6_ptr + 8, ipv6_ptr + 24, packet.ipv6Header.src_ip.begin());
    std::copy(ipv6_ptr + 24, ipv6_ptr + 40, packet.ipv6Header.des_ip.begin());

    // Store the original IP header and determine the IP protocol
    packet.OriginalIpHeader = packet.ipv6Header;
    packet.ip_protocol = get_ip_protocol(packet.ipv6Header.next_header);

    std::cout << "Detected Protocol: " << static_cast<uint8_t>(packet.ip_protocol) << std::endl;
}

void PacketParser::parse_tcp(const std::vector<char>& data, size_t length, Packet& packet) {
    // Determine the offset for the TCP header based on the EtherType
    size_t tcp_offset = (packet.ethFrame.ethertype == Packet::EtherType::IPv4) ? VALID_ETHER_LEN + VALID_IPV4_LEN : VALID_ETHER_LEN + VALID_IPV6_LEN;

    // Ensure the packet is long enough to contain the TCP header
    if(length < tcp_offset + VALID_TCP_LEN) {
        throw std::runtime_error("Invalid TCP packet length");
    }

    const char* tcp_ptr = data.data() + tcp_offset;

    // Parse the TCP header fields
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

void PacketParser::parse_udp(const std::vector<char>& data, size_t length, Packet& packet) {
    // Determine the offset for the UDP header based on the EtherType
    size_t udp_offset = (packet.ethFrame.ethertype == Packet::EtherType::IPv4) ? VALID_ETHER_LEN + VALID_IPV4_LEN : VALID_ETHER_LEN + VALID_IPV6_LEN;

    // Ensure the packet is long enough to contain the UDP header
    if(length < udp_offset + VALID_UDP_LEN) {
        throw std::runtime_error("Invalid UDP packet length");
    }

    const char* udp_ptr = data.data() + udp_offset;

    // Parse the UDP header fields
    packet.udpHeader.srcPort = (udp_ptr[0] << 8) | udp_ptr[1];
    packet.udpHeader.destPort = (udp_ptr[2] << 8) | udp_ptr[3];
    packet.udpHeader.length = (udp_ptr[4] << 8) | udp_ptr[5];
    packet.udpHeader.checksum = (udp_ptr[6] << 8) | udp_ptr[7];
}

void PacketParser::parse_icmpv4(const std::vector<char>& data, size_t length, Packet& packet) {
    size_t icmp_offset = VALID_ETHER_LEN + VALID_IPV4_LEN;

    // Ensure the packet is long enough to contain the ICMP header
    if(length < icmp_offset + VALID_ICMP_LEN) {
        throw std::runtime_error("Invalid ICMP packet length");
    }

    const char* icmp_ptr = data.data() + icmp_offset;

    // Parse the ICMP header fields
    packet.icmpHeader.type = static_cast<uint8_t>(icmp_ptr[0]);
    packet.icmpHeader.code = static_cast<uint8_t>(icmp_ptr[1]);
    packet.icmpHeader.checksum = static_cast<uint16_t>((icmp_ptr[2] << 8) | icmp_ptr[3]);

    // Handle different ICMP types
    switch(packet.icmpHeader.type) {
        case 0:
        case 8: {
            // Echo Request or Echo Reply
            Packet::ICMPEcho echo = {
                .identifier = static_cast<uint16_t>((icmp_ptr[4] << 8) | icmp_ptr[5]),
                .sequenceNumber = static_cast<uint16_t>((icmp_ptr[6] << 8) | icmp_ptr[7])
            };
            packet.icmpHeader.icmpData = echo;
            break;
        }
        case 3: {
            // Destination Unreachable
            Packet::ICMPDestinationUnreachable dest = {
                .unused = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .OriginalIpHeader = packet.OriginalIpHeader,
            };
            packet.icmpHeader.icmpData = dest;
            break;
        }
        case 5: {
            // Redirect
            Packet::ICMPRedirect redirect = {
                .gatewayAddress = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .OriginalIpHeader = packet.OriginalIpHeader,
            };
            packet.icmpHeader.icmpData = redirect;
            break;
        }
        case 11: {
            // Time Exceeded
            Packet::ICMPTimeExceeded timeExc = {
                .unused = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .OriginalIpHeader = packet.OriginalIpHeader,
            };
            packet.icmpHeader.icmpData = timeExc;
            break;
        }
        case 13:
        case 14: {
            // Timestamp Request or Timestamp Reply
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
        case 18: {
            // Address Mask Request or Address Mask Reply
            Packet::ICMPAddressMask addrMask = {
                .identifier = (icmp_ptr[4] << 8) | icmp_ptr[5],
                .sequenceNumber = (icmp_ptr[6] << 8) | icmp_ptr[7],
                .addressMask = (icmp_ptr[8] << 24) | (icmp_ptr[9] << 16) | (icmp_ptr[10] << 8) | icmp_ptr[11]
            };
            packet.icmpHeader.icmpData = addrMask;
            break;
        }
        default: {
            // Unsupported ICMP type
            Packet::ICMPGeneric gen = {
                .rest_of_header = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .payload = std::vector<uint8_t>(icmp_ptr + 8, icmp_ptr + length),
            };
            packet.icmpHeader.icmpData = std::move(gen);
            std::cerr << "Unsupported or unhandled ICMP type: " << static_cast<uint16_t>(packet.icmpHeader.type) << std::endl;
            break;
        }
    }
}

void PacketParser::parse_icmpv6(const std::vector<char>& data, size_t length, Packet& packet) {
    size_t icmp_offset = VALID_ETHER_LEN + VALID_IPV6_LEN;

    // Ensure the packet is long enough to contain the ICMPv6 header
    if(length < icmp_offset + VALID_ICMP_LEN) {
        throw std::runtime_error("Invalid ICMPv6 packet length");
    }

    const char* icmp_ptr = data.data() + icmp_offset;

    // Parse the ICMPv6 header fields
    packet.icmpHeader.type = static_cast<uint8_t>(icmp_ptr[0]);
    packet.icmpHeader.code = static_cast<uint8_t>(icmp_ptr[1]);
    packet.icmpHeader.checksum = static_cast<uint16_t>((icmp_ptr[2] << 8) | icmp_ptr[3]);

    // Handle different ICMPv6 types
    switch(packet.icmpHeader.type) {
        case 128:
        case 129: {
            // Echo Request or Echo Reply
            Packet::ICMPv6Echo echo = {
                .id = (icmp_ptr[4] << 8) | icmp_ptr[5],
                .sequence_num = (icmp_ptr[6] << 8) | icmp_ptr[7]
            };
            packet.icmpHeader.icmpData = echo;
            break;
        }
        case 1: {
            // Destination Unreachable
            Packet::ICMPv6DestUnreachable dest = {
                .unused = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .payload = std::vector<uint8_t>(icmp_ptr + 8, icmp_ptr + length)
            };
            packet.icmpHeader.icmpData = dest;
            break;
        }
        case 2: {
            // Packet Too Big
            Packet::ICMPv6PacketTooBig tooBig = {
                .mtu = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .payload = std::vector<uint8_t>(icmp_ptr + 8, icmp_ptr + length)
            };
            packet.icmpHeader.icmpData = tooBig;
            break;
        }
        case 3: {
            // Time Exceeded
            Packet::ICMPv6TimeExceeded timeExc = {
                .unused = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .payload = std::vector<uint8_t>(icmp_ptr + 8, icmp_ptr + length)
            };
            packet.icmpHeader.icmpData = timeExc;
            break;
        }
        case 4: {
            // Parameter Problem
            Packet::ICMPv6ParamProblem paramProb = {
                .pointer = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7],
                .payload = std::vector<uint8_t>(icmp_ptr + 8, icmp_ptr + length)
            };
            packet.icmpHeader.icmpData = paramProb;
            break;
        }
        case 133: {
            // Router Solicitation
            Packet::ICMPv6RouterSolicit routerSolicit = {
                .reserved = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7]
            };
            packet.icmpHeader.icmpData = routerSolicit;
            break;
        }
        case 134: {
            // Router Advertisement
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
        case 135: {
            // Neighbor Solicitation
            Packet::ICMPv6NeighborSolicit neighborSolicit = {
                .reserved = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7]
            };
            std::copy(icmp_ptr + 8, icmp_ptr + 24, neighborSolicit.target_addr.begin());
            packet.icmpHeader.icmpData = neighborSolicit;
            break;
        }
        case 136: {
            // Neighbor Advertisement
            Packet::ICMPv6NeighborAdvert neighborAdv = {
                .flags = (icmp_ptr[4] << 24) | (icmp_ptr[5] << 16) | (icmp_ptr[6] << 8) | icmp_ptr[7]
            };
            std::copy(icmp_ptr + 8, icmp_ptr + 24, neighborAdv.target_addr.begin());
            packet.icmpHeader.icmpData = neighborAdv;
            break;
        }
        default: {
            // Unsupported ICMPv6 type
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

Packet::IpProtocol PacketParser::get_ip_protocol(const uint8_t& protocol) {
    // Map the protocol number to the corresponding IP protocol enum
    switch(protocol) {
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
    // Map the EtherType number to the corresponding EtherType enum
    switch (type) {
        case 0x0800: etherType = Packet::EtherType::IPv4; break;
        case 0x86DD: etherType = Packet::EtherType::IPv6; break;
        case 0x0806: etherType = Packet::EtherType::ARP;  break;
        case 0x8100: etherType = Packet::EtherType::VLAN; break;
        case 0x8035: etherType = Packet::EtherType::RARP; break;
        default:
            // Log unknown EtherType for debugging purposes
            std::cerr << "Warning: Unknown EtherType: 0x" << std::hex << type << std::endl;
            etherType = Packet::EtherType::UNKNOWN;
            break;
    }
}

bool PacketParser::is_extension_header(const uint8_t& header) {
    // Check if the header is an extension header
    static const std::unordered_set<uint8_t> extension_headers = {0, 43, 44, 50, 60};
    return extension_headers.find(header) != extension_headers.end();
}
