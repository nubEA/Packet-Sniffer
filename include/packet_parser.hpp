#ifndef PACKET_PARSER_HPP
#define PACKET_PARSER_HPP

#include <array>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include "packet_structure.hpp"
#include <sstream>
#include <iostream>

class PacketParser {
public:
    struct EthernetFrame {
        std::array<uint8_t, 6> dest_mac{};        // Destination MAC address
        std::array<uint8_t, 6> src_mac{};         // Source MAC address
        Packet::EtherType ethertype = Packet::EtherType::UNKNOWN; // EtherType
    };

    struct IPv4Header {
        uint8_t version_ihl = 0;         // Version + IHL
        uint8_t tos = 0;                 // Type of Service
        uint16_t total_length = 0;       // Total length
        uint16_t identification = 0;     // Identification
        uint16_t flags_fragment = 0;     // Flags + Fragment offset
        uint8_t ttl = 0;                 // Time to Live
        uint8_t protocol = 0;            // Protocol (e.g., TCP=6)
        uint16_t header_checksum = 0;    // Header checksum
        std::array<uint8_t, 4> src_ip{}; // Source IP address
        std::array<uint8_t, 4> dest_ip{};// Destination IP address
    };

    struct IPv6Header {
        uint8_t version = 0;              // IPv6 version
        uint8_t traffic_class = 0;        // Traffic class
        uint32_t flow_label = 0;          // Flow label
        uint16_t payload_length = 0;      // Payload length
        uint8_t next_header = 0;          // Next header (protocol)
        uint8_t hop_limit = 0;            // Hop limit
        std::array<uint8_t, 16> src_ip{}; // Source IPv6 address
        std::array<uint8_t, 16> des_ip{}; // Destination IPv6 address
    };

    EthernetFrame ethFrame;  // Ethernet frame data
    IPv4Header ipv4Header;   // IPv4 header data
    IPv6Header ipv6Header;   // IPv6 header data

public:
    // Parses raw packet data and returns a Packet object
    static Packet parse_packet(const std::vector<char>& data, size_t length);

private:
    // Parses the Ethernet header and updates the Packet object
    static void parse_ether_header(const std::vector<char>& data, size_t length, Packet& packet);

    // Parses the IPv4 header and updates the Packet object
    static void parse_ipv4(const std::vector<char>& data, size_t length, Packet& packet);

    // Parses the IPv6 header and updates the Packet object
    static void parse_ipv6(const std::vector<char>& data, size_t length, Packet& packet);

    // Maps a raw EtherType value to the Packet::EtherType enum
    static void assign_ether_type(uint16_t type, Packet::EtherType& etherType);

    // Parses the TCP header and updates the Packet object
    static void parse_tcp(const std::vector<char>& data, size_t length, Packet& packet);

    // Parses the UDP header and updates the Packet object
    static void parse_udp(const std::vector<char>& data, size_t length, Packet& packet);

    // Parses the ICMP header and updates the Packet object
    static void parse_icmpv4(const std::vector<char>& data, size_t length, Packet& packet);
    static void parse_icmpv6(const std::vector<char>& data, size_t length, Packet& packet);

    // Maps a raw IP protocol value to the Packet::IpProtocol enum
    static Packet::IpProtocol get_ip_protocol(const uint8_t protocol);

};

#endif // PACKET_PARSER_HPP
