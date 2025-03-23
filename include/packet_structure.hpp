#ifndef PACKET_STRUCTURE_HPP
#define PACKET_STRUCTURE_HPP

#include <vector>
#include <cstdint>
#include <array>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdint.h>
#include <variant>

class Packet{
    public:
        //Will be used to filter traffic based on the protocol that the payload is carrying
        enum class EtherType : uint16_t {
            IPv4 = 0x0800,   // Internet Protocol version 4
            IPv6 = 0x86DD,   // Internet Protocol version 6
            ARP  = 0x0806,   // Address Resolution Protocol
            VLAN = 0x8100,   // VLAN-tagged frame
            RARP = 0x8035,   // Reverse Address Resolution Protocol
            UNKNOWN = 0xFFFF 
        };
        // Ethernet Frame Structure
        struct EthernetFrame {
            std::array<unsigned char,6> dest_mac;
            std::array<unsigned char,6> src_mac;
            EtherType ethertype;  
        };

        // IPv4 Header Structure
        struct IPv4Header {
            uint8_t version_ihl;
            uint8_t tos;
            uint16_t total_length;
            uint16_t identification;
            uint16_t flags_fragment;
            uint8_t ttl;
            uint8_t protocol;
            uint16_t header_checksum;
            uint32_t src_ip;
            uint32_t dest_ip;
        };

        struct IPv6Header{
            uint8_t version;
            uint8_t traffic_class;
            uint32_t flow_label;
            uint16_t payload_length;
            uint8_t next_header;
            uint8_t hop_limit;
            std::array<uint8_t, 16> src_ip;
            std::array<uint8_t, 16> des_ip;
        };

        struct TCPHeader {
            uint16_t srcPort;
            uint16_t destPort;
            uint32_t seqNum;
            uint32_t ackNum;
            uint8_t dataOffset;
            uint8_t flags;
            uint16_t windowSize;
            uint16_t checksum;
            uint16_t urgentPointer;
        };

        struct UDPHeader {
            uint16_t srcPort;
            uint16_t destPort;
            uint16_t length;
            uint16_t checksum;
        };

        struct ICMPHeader {
            uint8_t type;
            uint8_t code;
            uint16_t checksum;
            // Additional fields depending on type
        };

        std::variant<IPv4Header, IPv6Header> OriginalIpHeader;
        // ICMP Echo Request/Reply Structure
        struct ICMPEcho {
            uint16_t identifier;       // Identifier (used for matching requests/replies)
            uint16_t sequenceNumber;   // Sequence number (used for matching requests/replies)
            std::vector<uint8_t> payload; // Optional data (e.g., ping payload)
        };

        // ICMP Destination Unreachable Structure
        struct ICMPDestinationUnreachable {
            uint32_t unused;                     // 4 bytes of unused data
            std::variant<IPv4Header, IPv6Header> OriginalIpHeader; // Original IP header (IPv4 or IPv6)
            std::array<uint8_t, 8> originalPayload; // First 8 bytes of the original packet's payload
        };

        // ICMP Time Exceeded Structure
        struct ICMPTimeExceeded {
            uint32_t unused;                     // 4 bytes of unused data
            std::variant<IPv4Header, IPv6Header> OriginalIpHeader; // Original IP header (IPv4 or IPv6)
            std::array<uint8_t, 8> originalPayload; // First 8 bytes of the original packet's payload
        };

        // ICMP Redirect Structure
        struct ICMPRedirect {
            uint32_t gatewayAddress;             // Address of the gateway to which traffic should be sent
            std::variant<IPv4Header, IPv6Header> OriginalIpHeader; // Original IP header (IPv4 or IPv6)
            std::array<uint8_t, 8> originalPayload; // First 8 bytes of the original packet's payload
        };

        // ICMP Timestamp Request/Reply Structure
        struct ICMPTimestamp {
            uint16_t identifier;       // Identifier (used for matching requests/replies)
            uint16_t sequenceNumber;   // Sequence number (used for matching requests/replies)
            uint32_t originateTimestamp; // Time when the request was sent
            uint32_t receiveTimestamp;   // Time when the request was received
            uint32_t transmitTimestamp;  // Time when the reply was sent
        };

        // ICMP Address Mask Request/Reply Structure
        struct ICMPAddressMask {
            uint16_t identifier;       // Identifier (used for matching requests/replies)
            uint16_t sequenceNumber;   // Sequence number (used for matching requests/replies)
            uint32_t addressMask;      // Subnet mask
        };

        // std::variant to handle different ICMP types
        std::variant<ICMPEcho, ICMPDestinationUnreachable, ICMPTimeExceeded, ICMPRedirect, ICMPTimestamp, ICMPAddressMask> icmpData;

        struct HTTPHeader {
            std::string method;     // GET, POST, etc.
            std::string path;       // URL path
            std::string version;    // HTTP/1.1, HTTP/2
            std::vector<std::pair<std::string, std::string>> headers;
            std::string body;       // For POST requests, etc.
        };
        

        struct EthernetFrame ethFrame{};
        struct IPv4Header ipv4Header{};
        struct IPv6Header ipv6Header{};
        struct TCPHeader tcpHeader{};
        struct UDPHeader udpHeader{};
        struct ICMPHeader icmpHeader{};

        std::vector<char> payload;
        uint32_t timestamp;
        uint16_t packet_len;
        
        const std::string get_mac_string(const std::array<unsigned char,6>& mac) const;
        const std::string get_ipv4_string(const uint32_t ip) const;
        const std::string get_ipv6_string(const std::array<uint8_t, 16>& ip) const;
};

#endif // PACKET_STRUCTURE_HPP
