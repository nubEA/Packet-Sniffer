#ifndef PACKET_PARSER_HPP
#define PACKET_PARSER_HPP

#include "packet_structure.hpp"
#include <vector>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <stdexcept>

class PacketParser {
public:
    static Packet parse_packet(const std::vector<char>& data, size_t length);
private:
    static void parse_ether_header(const std::string& data, size_t length, Packet& packet);
    static void assign_ether_type(uint16_t type, Packet::EtherType& etherType);
};

#endif // PACKET_PARSER_HPP
