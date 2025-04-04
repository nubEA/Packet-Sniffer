#ifndef PACKET_PRINTER_HPP
#define PACKET_PRINTER_HPP

#include <iostream>
#include <iomanip>
#include <string>
#include "packet_parser.hpp"
#include "packet_structure.hpp"
#include "colors.hpp"

class PacketPrinter {
public:
    static void print_packet(const Packet& packet);

private:
    static void print_ethernet(const Packet& packet);
    static void print_ipv4(const Packet& packet);
    static void print_ipv6(const Packet& packet);
    static void print_tcp(const Packet& packet);
    static void print_udp(const Packet& packet);
    static void print_icmp(const Packet& packet);

    static void print_http(const Packet& packet);
    static void print_dns(const Packet& packet);

    static void print_payload(const Packet& packet);
    static std::string ether_type_to_string(const Packet& packet);
    static std::string ip_protocol_to_string(const Packet& packet);
    static void print_transport_layer(const Packet& packet);

    static void print_separator();
};

#endif // PACKET_PRINTER_HPP
