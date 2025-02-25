#ifndef PACKET_STRUCTURE_HPP
#define PACKET_STRUCTURE_HPP

#include <vector>
#include <cstdint>
#include <array>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdint.h>

class Packet{
    public:
        // Ethernet Frame Structure
        struct EthernetFrame {
            std::array<uint8_t,6> dest_mac;
            std::array<uint8_t,6> src_mac;
            uint16_t ethertype;  
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

        struct EthernetFrame ethFrame{};
        struct IPv4Header ip4header{};

        const std::string get_mac_string(const std::array<uint8_t,6>& mac) const;
        const std::string get_ip_string(const uint32_t ip) const;
};
#endif // PACKET_STRUCTURE_HPP
