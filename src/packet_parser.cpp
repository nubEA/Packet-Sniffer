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
                    parse_transport_layer_headers(data, length, packet);
                }
                break;

            case Packet::EtherType::IPv6:
                // Ensure the packet is long enough to contain the IPv6 header
                if (length >= VALID_ETHER_LEN + VALID_IPV6_LEN) {
                    parse_ipv6(data, length, packet);
                    parse_transport_layer_headers(data, length, packet);
                }
                break;

            default:
                // Log unsupported EtherType for debugging purposes
                // std::cerr << "Unsupported or unhandled EtherType: "
                //         << std::hex << static_cast<uint16_t>(packet.ethFrame.ethertype)
                //         << std::endl;
                break;
        }
        return packet;
    }

    void PacketParser::parse_transport_layer_headers(const std::vector<char>& data, size_t length, Packet& packet)
    {
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
                // std::cerr << "Unsupported or unhandled IP Protocol: " << static_cast<uint8_t>(packet.ip_protocol) << std::endl;
                break;
            }
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
        uint16_t etherType = ntohs(reinterpret_cast<const uint16_t*>(data.data() + 12)[0]);
        
        assign_ether_type(etherType, packet.ethFrame.ethertype);
    }

    void PacketParser::parse_ipv4(const std::vector<char>& data, size_t length, Packet& packet) {
        size_t ipv4_offset = VALID_ETHER_LEN;

        size_t ipHeaderLengthBytes = (packet.ipv4Header.version_ihl & 0x0F) * 4; 
        packet.ipv4HeaderEndOffset = VALID_ETHER_LEN + ipHeaderLengthBytes;

        // Ensure the packet is long enough to contain the IPv4 header
        if (length < ipv4_offset + VALID_IPV4_LEN) {
            throw std::runtime_error("Invalid IPv4 packet length");
        }

        const char* ipv4_ptr = data.data() + ipv4_offset;
        
        packet.ipv4Header.version_ihl     = static_cast<uint8_t>(ipv4_ptr[0]);
        packet.ipv4Header.tos             = static_cast<uint8_t>(ipv4_ptr[1]);
        packet.ipv4Header.total_length    = ntohs(*reinterpret_cast<const uint16_t*>(ipv4_ptr + 2));
        packet.ipv4Header.identification  = ntohs(*reinterpret_cast<const uint16_t*>(ipv4_ptr + 4));
        packet.ipv4Header.flags_fragment  = ntohs(*reinterpret_cast<const uint16_t*>(ipv4_ptr + 6));
        packet.ipv4Header.ttl             = static_cast<uint8_t>(ipv4_ptr[8]);
        packet.ipv4Header.protocol        = static_cast<uint8_t>(ipv4_ptr[9]);
        packet.ipv4Header.header_checksum = ntohs(*reinterpret_cast<const uint16_t*>(ipv4_ptr + 10));

        // Copy the source and destination IP addresses
        std::copy(ipv4_ptr + 12, ipv4_ptr + 16, reinterpret_cast<char*>(&packet.ipv4Header.src_ip));
        std::copy(ipv4_ptr + 16, ipv4_ptr + 20, reinterpret_cast<char*>(&packet.ipv4Header.dest_ip));
        packet.ipv4Header.src_ip = ntohl(packet.ipv4Header.src_ip);
        packet.ipv4Header.dest_ip = ntohl(packet.ipv4Header.dest_ip);
        // Store the original IP header and determine the IP protocol
        packet.OriginalIpHeader = packet.ipv4Header;
        packet.ip_protocol = get_ip_protocol(packet.ipv4Header.protocol);
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
        packet.ipv6Header.payload_length = ntohs(reinterpret_cast<const uint16_t*>(ipv6_ptr + 4)[0]); // Extract payload length from bytes 4-5

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
        packet.ipv6HeaderEndOffset = currLength;
    }

    void PacketParser::parse_tcp(const std::vector<char>& data, size_t length, Packet& packet) {
        // Determine the offset for the TCP header based on the EtherType
        size_t tcp_offset = (packet.ethFrame.ethertype == Packet::EtherType::IPv4) ? packet.ipv4HeaderEndOffset : packet.ipv6HeaderEndOffset;

        // Ensure the packet is long enough to contain the TCP header
        if(length < tcp_offset + VALID_TCP_LEN) {
            throw std::runtime_error("Invalid TCP packet length");
        }

        const char* tcp_ptr = data.data() + tcp_offset;

        // Parse the TCP header fields
        packet.tcpHeader.srcPort = ntohs(reinterpret_cast<const uint16_t*>(tcp_ptr)[0]);
        packet.tcpHeader.destPort = ntohs(reinterpret_cast<const uint16_t*>(tcp_ptr+2)[0]);
        packet.tcpHeader.seqNum = ntohl(reinterpret_cast<const uint32_t*>(tcp_ptr+4)[0]);
        packet.tcpHeader.ackNum = ntohl(reinterpret_cast<const uint32_t*>(tcp_ptr+8)[0]);
        packet.tcpHeader.dataOffset = (tcp_ptr[12] >> 4) & 0x0F;                            // Data offset field tells us where the payload actually starts
        packet.tcpHeader.flags = tcp_ptr[13];
        packet.tcpHeader.windowSize = ntohs(reinterpret_cast<const uint16_t*>(tcp_ptr+14)[0]);
        packet.tcpHeader.checksum = ntohs(reinterpret_cast<const uint16_t*>(tcp_ptr+16)[0]);    
        packet.tcpHeader.urgentPointer = ntohs(reinterpret_cast<const uint16_t*>(tcp_ptr+18)[0]);

        if(packet.tcpHeader.dataOffset*4 < VALID_TCP_LEN) throw std::runtime_error("Invalid TCP header length");

        size_t tcpHeaderLengthBytes = packet.tcpHeader.dataOffset * 4;
        size_t payloadOffset =  tcp_offset + packet.tcpHeader.dataOffset*4;

        size_t ipTotalLength; // Includes IP Header + (TCP Header + TCP Payload)
        size_t ipHeaderLength; // Just the IP Header length

        if (packet.ethFrame.ethertype == Packet::EtherType::IPv4) {
            // Use ntohs for network-to-host short conversion!
            ipTotalLength = ntohs(packet.ipv4Header.total_length);
            ipHeaderLength = (packet.ipv4Header.version_ihl & 0x0F) * 4;
        } else { // IPv6
            // payload_length is *just* the payload after the base 40-byte header
            // Total length from IP start = base header + extensions + L4 = 40 + payload_length
            ipTotalLength = VALID_IPV6_LEN + ntohs(packet.ipv6Header.payload_length);
            // The effective IP header length *including extensions* is needed
            // We calculated the end offset, so length = end_offset - eth_len
            ipHeaderLength = packet.ipv6HeaderEndOffset - VALID_ETHER_LEN;
        }   
        
        if (ipTotalLength < ipHeaderLength + VALID_TCP_LEN) {
            throw std::runtime_error("Inconsistent IP total length for TCP packet");
        }
        // Total header size before TCP payload = IP header length + TCP header length
        size_t totalHeadersLength = ipHeaderLength + tcpHeaderLengthBytes;
        size_t expectedPayloadLength = ipTotalLength - totalHeadersLength;
        
        size_t availableDataLength = (length > payloadOffset) ? (length - payloadOffset) : 0;
        packet.payloadLength = std::min(expectedPayloadLength, availableDataLength);

        // Check if ipTotalLength makes sense (at least IP header + min TCP header)

        packet.payload = std::vector<char>(data.begin() + payloadOffset, data.begin() + payloadOffset + packet.payloadLength);
        
        if((packet.tcpHeader.srcPort == 80 || packet.tcpHeader.destPort == 80) && HttpParser::is_likely_http_payload(packet.payload))
        {
            if(packet.payload.empty()) throw std::runtime_error("Empty HTTP payload");

            packet.httpData = HttpParser::parse_http(packet.payload);
        }
    }

    void PacketParser::parse_udp(const std::vector<char>& data, size_t length, Packet& packet) {
        // Determine the offset for the UDP header based on the EtherType
        size_t udp_offset = (packet.ethFrame.ethertype == Packet::EtherType::IPv4) ? packet.ipv4HeaderEndOffset : packet.ipv6HeaderEndOffset;

        // Ensure the packet is long enough to contain the UDP header
        if(length < udp_offset + VALID_UDP_LEN) {
            throw std::runtime_error("Invalid UDP packet length");
        }

        const char* udp_ptr = data.data() + udp_offset;

        // Parse the UDP header fields
        packet.udpHeader.srcPort = ntohs(reinterpret_cast<const uint16_t*>(udp_ptr)[0]);
        packet.udpHeader.destPort = ntohs(reinterpret_cast<const uint16_t*>(udp_ptr+2)[0]);
        packet.udpHeader.length = ntohs(reinterpret_cast<const uint16_t*>(udp_ptr+4)[0]);
        packet.udpHeader.checksum = ntohs(reinterpret_cast<const uint16_t*>(udp_ptr+6)[0]);

        size_t payloadOffset = udp_offset + VALID_UDP_LEN;

        uint16_t udpTotalLength = ntohs(packet.udpHeader.length);

        // Sanity check: Must be at least the header size
        if (udpTotalLength < VALID_UDP_LEN) {
            throw std::runtime_error("Invalid UDP length field (too small)");
        }
        size_t expectedPayloadLength = static_cast<size_t>(udpTotalLength) - VALID_UDP_LEN;
        size_t availableDataLength = (length > payloadOffset) ? (length - payloadOffset) : 0;

        packet.payloadLength = std::min(expectedPayloadLength, availableDataLength);
        packet.payload = std::vector<char>(data.begin() + payloadOffset, data.begin() + payloadOffset + packet.payloadLength);
    }

    void PacketParser::parse_icmpv4(const std::vector<char>& data, size_t length, Packet& packet) {
        size_t icmp_offset = packet.ipv4HeaderEndOffset;

        if (length < icmp_offset + VALID_ICMP_LEN) {
            throw std::runtime_error("Invalid ICMPv4 packet length (too short for basic header)");
        }

        const char* icmp_ptr = data.data() + icmp_offset;

        packet.icmpHeader.type = static_cast<uint8_t>(icmp_ptr[0]);
        packet.icmpHeader.code = static_cast<uint8_t>(icmp_ptr[1]);
        packet.icmpHeader.checksum = ntohs(*reinterpret_cast<const uint16_t*>(icmp_ptr + 2));

        size_t ipTotalLength = 0;
        size_t ipHeaderLength = 0;
        if (std::holds_alternative<Packet::IPv4Header>(packet.OriginalIpHeader)) {
            const auto& ipHdr = std::get<Packet::IPv4Header>(packet.OriginalIpHeader);
            ipTotalLength = ntohs(ipHdr.total_length);
            ipHeaderLength = (ipHdr.version_ihl & 0x0F) * 4;
        } else {
            throw std::runtime_error("Mismatched IP header type during ICMPv4 parsing");
        }

        switch (packet.icmpHeader.type) {
            case 0: // Echo Reply
            case 8: { // Echo Request
                if (length < icmp_offset + 8) {
                    throw std::runtime_error("Invalid ICMPv4 Echo packet length (too short for id/seq)");
                }
                Packet::ICMPEcho echo = {
                    .identifier = ntohs(*reinterpret_cast<const uint16_t*>(icmp_ptr + 4)),
                    .sequenceNumber = ntohs(*reinterpret_cast<const uint16_t*>(icmp_ptr + 6))
                };
                packet.icmpHeader.icmpData = std::move(echo);
                break;
            }
            case 3: { // Destination Unreachable
                if (length < icmp_offset + 8) {
                    throw std::runtime_error("Invalid ICMPv4 Dest Unreachable length (too short for unused/header)");
                }
                Packet::ICMPDestinationUnreachable dest = {
                    .unused = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 4)),
                    .OriginalIpHeader = packet.OriginalIpHeader,
                };
                packet.icmpHeader.icmpData = std::move(dest);
                break;
            }
            case 5: { // Redirect
                if (length < icmp_offset + 8) {
                    throw std::runtime_error("Invalid ICMPv4 Redirect length (too short for gateway/header)");
                }
                Packet::ICMPRedirect redirect = {
                    .gatewayAddress = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 4)),
                    .OriginalIpHeader = packet.OriginalIpHeader,
                };
                packet.icmpHeader.icmpData = std::move(redirect);
                break;
            }
            case 11: { // Time Exceeded
                if (length < icmp_offset + 8) {
                    throw std::runtime_error("Invalid ICMPv4 Time Exceeded length (too short for unused/header)");
                }
                Packet::ICMPTimeExceeded timeExc = {
                    .unused = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 4)),
                    .OriginalIpHeader = packet.OriginalIpHeader,
                };
                packet.icmpHeader.icmpData = std::move(timeExc);
                break;
            }
            case 13: // Timestamp
            case 14: { // Timestamp Reply
                if (length < icmp_offset + 20) {
                    throw std::runtime_error("Invalid ICMPv4 Timestamp length (too short for timestamps)");
                }
                Packet::ICMPTimestamp timest = {
                    .identifier = ntohs(*reinterpret_cast<const uint16_t*>(icmp_ptr + 4)),
                    .sequenceNumber = ntohs(*reinterpret_cast<const uint16_t*>(icmp_ptr + 6)),
                    .originateTimestamp = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 8)),
                    .receiveTimestamp = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 12)),
                    .transmitTimestamp = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 16))
                };
                packet.icmpHeader.icmpData = std::move(timest);
                break;
            }
            case 17: // Address Mask Request
            case 18: { // Address Mask Reply
                if (length < icmp_offset + 12) {
                    throw std::runtime_error("Invalid ICMPv4 Address Mask length (too short for mask)");
                }
                Packet::ICMPAddressMask addrMask = {
                    .identifier = ntohs(*reinterpret_cast<const uint16_t*>(icmp_ptr + 4)),
                    .sequenceNumber = ntohs(*reinterpret_cast<const uint16_t*>(icmp_ptr + 6)),
                    .addressMask = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 8))
                };
                packet.icmpHeader.icmpData = std::move(addrMask);
                break;
            }
            default: {
                if (length < icmp_offset + 8) {
                    throw std::runtime_error("Invalid ICMPv4 Generic packet length (too short for rest_of_header)");
                }
                Packet::ICMPGeneric gen = {
                    .rest_of_header = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 4)),
                };

                size_t icmpFixedPartLength = 8;
                size_t payloadOffset = icmp_offset + icmpFixedPartLength;

                size_t totalHeadersLength = ipHeaderLength + icmpFixedPartLength;
                size_t expectedPayloadLength = 0;
                if (ipTotalLength >= totalHeadersLength) {
                    expectedPayloadLength = ipTotalLength - totalHeadersLength;
                } else {
                    // std::cerr << "Warning: IP total length (" << ipTotalLength
                    //         << ") less than headers (" << totalHeadersLength
                    //         << ") for ICMPv4 type " << (int)packet.icmpHeader.type << std::endl;
                }

                size_t availableDataLength = (length > payloadOffset) ? (length - payloadOffset) : 0;
                size_t finalPayloadLength = std::min(expectedPayloadLength, availableDataLength);

                const char* payloadStartPtr = data.data() + payloadOffset;
                gen.payload.assign(reinterpret_cast<const uint8_t*>(payloadStartPtr),
                                reinterpret_cast<const uint8_t*>(payloadStartPtr + finalPayloadLength));

                packet.icmpHeader.icmpData = std::move(gen);
                // std::cerr << "Parsed unknown/unhandled ICMPv4 type: " << static_cast<uint16_t>(packet.icmpHeader.type) << std::endl;
                break;
            }
        }
    }

    void PacketParser::parse_icmpv6(const std::vector<char>& data, size_t length, Packet& packet) {
        size_t icmp_offset = packet.ipv6HeaderEndOffset;

        if (length < icmp_offset + VALID_ICMP_LEN) {
            throw std::runtime_error("Invalid ICMPv6 packet length (too short for basic header)");
        }

        const char* icmp_ptr = data.data() + icmp_offset;

        packet.icmpHeader.type = static_cast<uint8_t>(icmp_ptr[0]);
        packet.icmpHeader.code = static_cast<uint8_t>(icmp_ptr[1]);
        packet.icmpHeader.checksum = ntohs(*reinterpret_cast<const uint16_t*>(icmp_ptr + 2));

        size_t ipPayloadLength = 0;
        size_t ipHeaderLength = 0;

        if (std::holds_alternative<Packet::IPv6Header>(packet.OriginalIpHeader)) {
            const auto& ipHdr = std::get<Packet::IPv6Header>(packet.OriginalIpHeader);
            ipPayloadLength = ntohs(ipHdr.payload_length);
            ipHeaderLength = packet.ipv6HeaderEndOffset - VALID_ETHER_LEN;
        } else {
            throw std::runtime_error("Mismatched IP header type during ICMPv6 parsing");
        }

        switch (packet.icmpHeader.type) {
            case 128: // Echo Request
            case 129: { // Echo Reply
                if (length < icmp_offset + 8) {
                    throw std::runtime_error("Invalid ICMPv6 Echo packet length (too short for id/seq)");
                }
                Packet::ICMPv6Echo echo = {
                    .id = ntohs(*reinterpret_cast<const uint16_t*>(icmp_ptr + 4)),
                    .sequence_num = ntohs(*reinterpret_cast<const uint16_t*>(icmp_ptr + 6))
                };
                packet.icmpHeader.icmpData = std::move(echo);
                break;
            }

            case 1: { // Destination Unreachable
                if (length < icmp_offset + 8) {
                    throw std::runtime_error("Invalid ICMPv6 Dest Unreachable length (too short for unused)");
                }
                Packet::ICMPv6DestUnreachable dest = {
                    .unused = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 4)),
                };

                size_t icmpFixedPartLength = 8;
                size_t payloadOffset = icmp_offset + icmpFixedPartLength;
                size_t totalICMPMessageLength = ipPayloadLength - (ipHeaderLength - VALID_IPV6_LEN);

                size_t expectedPayloadLength = 0;
                if (totalICMPMessageLength >= icmpFixedPartLength) {
                    expectedPayloadLength = totalICMPMessageLength - icmpFixedPartLength;
                }

                size_t availableDataLength = (length > payloadOffset) ? (length - payloadOffset) : 0;
                size_t finalPayloadLength = std::min(expectedPayloadLength, availableDataLength);

                const char* payloadStartPtr = data.data() + payloadOffset;
                dest.payload.assign(reinterpret_cast<const uint8_t*>(payloadStartPtr),
                                    reinterpret_cast<const uint8_t*>(payloadStartPtr + finalPayloadLength));

                packet.icmpHeader.icmpData = std::move(dest);
                break;
            }
            case 2: { // Packet Too Big
                if (length < icmp_offset + 8) {
                    throw std::runtime_error("Invalid ICMPv6 Packet Too Big length (too short for MTU)");
                }
                Packet::ICMPv6PacketTooBig tooBig = {
                    .mtu = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 4)),
                };

                size_t icmpFixedPartLength = 8;
                size_t payloadOffset = icmp_offset + icmpFixedPartLength;
                size_t totalICMPMessageLength = ipPayloadLength - (ipHeaderLength - VALID_IPV6_LEN);

                size_t expectedPayloadLength = 0;
                if (totalICMPMessageLength >= icmpFixedPartLength) {
                    expectedPayloadLength = totalICMPMessageLength - icmpFixedPartLength;
                }

                size_t availableDataLength = (length > payloadOffset) ? (length - payloadOffset) : 0;
                size_t finalPayloadLength = std::min(expectedPayloadLength, availableDataLength);

                const char* payloadStartPtr = data.data() + payloadOffset;
                tooBig.payload.assign(reinterpret_cast<const uint8_t*>(payloadStartPtr),
                                    reinterpret_cast<const uint8_t*>(payloadStartPtr + finalPayloadLength));

                packet.icmpHeader.icmpData = std::move(tooBig);
                break;
            }
            case 3: { // Time Exceeded
                if (length < icmp_offset + 8) {
                    throw std::runtime_error("Invalid ICMPv6 Time Exceeded length (too short for unused)");
                }
                Packet::ICMPv6TimeExceeded timeExc = {
                    .unused = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 4)),
                };

                size_t icmpFixedPartLength = 8;
                size_t payloadOffset = icmp_offset + icmpFixedPartLength;
                size_t totalICMPMessageLength = ipPayloadLength - (ipHeaderLength - VALID_IPV6_LEN);

                size_t expectedPayloadLength = 0;
                if (totalICMPMessageLength >= icmpFixedPartLength) {
                    expectedPayloadLength = totalICMPMessageLength - icmpFixedPartLength;
                }

                size_t availableDataLength = (length > payloadOffset) ? (length - payloadOffset) : 0;
                size_t finalPayloadLength = std::min(expectedPayloadLength, availableDataLength);

                const char* payloadStartPtr = data.data() + payloadOffset;
                timeExc.payload.assign(reinterpret_cast<const uint8_t*>(payloadStartPtr),
                                    reinterpret_cast<const uint8_t*>(payloadStartPtr + finalPayloadLength));

                packet.icmpHeader.icmpData = std::move(timeExc);
                break;
            }
            case 4: { // Parameter Problem
                if (length < icmp_offset + 8) {
                    throw std::runtime_error("Invalid ICMPv6 Parameter Problem length (too short for pointer)");
                }
                Packet::ICMPv6ParamProblem paramProb = {
                    .pointer = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 4)),
                };

                size_t icmpFixedPartLength = 8;
                size_t payloadOffset = icmp_offset + icmpFixedPartLength;
                size_t totalICMPMessageLength = ipPayloadLength - (ipHeaderLength - VALID_IPV6_LEN);

                size_t expectedPayloadLength = 0;
                if (totalICMPMessageLength >= icmpFixedPartLength) {
                    expectedPayloadLength = totalICMPMessageLength - icmpFixedPartLength;
                }

                size_t availableDataLength = (length > payloadOffset) ? (length - payloadOffset) : 0;
                size_t finalPayloadLength = std::min(expectedPayloadLength, availableDataLength);

                const char* payloadStartPtr = data.data() + payloadOffset;
                paramProb.payload.assign(reinterpret_cast<const uint8_t*>(payloadStartPtr),
                                        reinterpret_cast<const uint8_t*>(payloadStartPtr + finalPayloadLength));

                packet.icmpHeader.icmpData = std::move(paramProb);
                break;
            }
            case 133: { // Router Solicitation
                if (length < icmp_offset + 8) {
                    throw std::runtime_error("Invalid ICMPv6 Router Solicitation length");
                }
                Packet::ICMPv6RouterSolicit routerSolicit = {
                    .reserved = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 4))
                };
                packet.icmpHeader.icmpData = std::move(routerSolicit);
                break;
            }
            case 134: { // Router Advertisement
                if (length < icmp_offset + 16) {
                    throw std::runtime_error("Invalid ICMPv6 Router Advertisement length");
                }
                Packet::ICMPv6RouterAdvert routerAdv = {
                    .hop_limit = static_cast<uint8_t>(icmp_ptr[4]),
                    .flags = static_cast<uint8_t>(icmp_ptr[5]),
                    .router_lifetime = ntohs(*reinterpret_cast<const uint16_t*>(icmp_ptr + 6)),
                    .reachable_time = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 8)),
                    .retransmit_time = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 12))
                };
                packet.icmpHeader.icmpData = std::move(routerAdv);
                break;
            }
            case 135: { // Neighbor Solicitation
                if (length < icmp_offset + 24) {
                    throw std::runtime_error("Invalid ICMPv6 Neighbor Solicitation length");
                }
                Packet::ICMPv6NeighborSolicit neighborSolicit = {
                    .reserved = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 4))
                };
                std::copy(icmp_ptr + 8, icmp_ptr + 24, neighborSolicit.target_addr.begin());
                packet.icmpHeader.icmpData = std::move(neighborSolicit);
                break;
            }
            case 136: { // Neighbor Advertisement
                if (length < icmp_offset + 24) {
                    throw std::runtime_error("Invalid ICMPv6 Neighbor Advertisement length");
                }
                Packet::ICMPv6NeighborAdvert neighborAdv = {
                    .flags = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 4))
                };
                std::copy(icmp_ptr + 8, icmp_ptr + 24, neighborAdv.target_addr.begin());
                packet.icmpHeader.icmpData = std::move(neighborAdv);
                break;
            }
            default: {
                if (length < icmp_offset + 8) {
                    throw std::runtime_error("Invalid ICMPv6 Generic packet length (too short for rest)");
                }
                Packet::ICMPv6Generic gen = {
                    .rest = ntohl(*reinterpret_cast<const uint32_t*>(icmp_ptr + 4)),
                };

                size_t icmpFixedPartLength = 8;
                size_t payloadOffset = icmp_offset + icmpFixedPartLength;
                size_t totalICMPMessageLength = ipPayloadLength - (ipHeaderLength - VALID_IPV6_LEN);

                size_t expectedPayloadLength = 0;
                if (totalICMPMessageLength >= icmpFixedPartLength) {
                    expectedPayloadLength = totalICMPMessageLength - icmpFixedPartLength;
                }


                size_t availableDataLength = (length > payloadOffset) ? (length - payloadOffset) : 0;
                size_t finalPayloadLength = std::min(expectedPayloadLength, availableDataLength);

                const char* payloadStartPtr = data.data() + payloadOffset;
                gen.payload.assign(reinterpret_cast<const uint8_t*>(payloadStartPtr),
                                reinterpret_cast<const uint8_t*>(payloadStartPtr + finalPayloadLength));

                packet.icmpHeader.icmpData = std::move(gen);
                std::cerr << "Parsed unknown/unhandled ICMPv6 type: " << static_cast<uint16_t>(packet.icmpHeader.type) << std::endl;
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
                // std::cerr << "Warning: Unknown EtherType: 0x" << std::hex << type << std::endl;
                etherType = Packet::EtherType::UNKNOWN;
                break;
        }
    }

    bool PacketParser::is_extension_header(const uint8_t& header) {
        // Check if the header is an extension header
        static const std::unordered_set<uint8_t> extension_headers = {0, 43, 44, 50, 60};
        return extension_headers.find(header) != extension_headers.end();
    }
