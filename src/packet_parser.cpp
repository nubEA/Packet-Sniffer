#include "packet_parser.hpp"

#define ETHERLEN 14

Packet PacketParser::parse_packet(const std::vector<char>& data, size_t length)
{
    Packet packet;

    std::string str(data.begin(),data.end());

    parse_ether_header(str,str.length(),packet);

    return packet;
}

void PacketParser::parse_ether_header(const std::string& data, size_t length, Packet& packet)
{
    std::array<uint8_t,6> destMac{};
    std::array<uint8_t,6> sourceMac{};

    if(length < ETHERLEN){
        std::cout << "Invalid packet length" << std::endl;
        throw std::runtime_error("Invalid packet length");
        return;
    }

    std::copy(data.begin(),data.begin()+6,destMac.begin());
    std::copy(data.begin()+6,data.begin()+12,sourceMac.begin());

    //Stoi over stringstream conversion as this is faster which is crucial for parsing packets
    //ether type in network byte order (big endian)
    // Extract EtherType (next 2 bytes) as a hexadecimal string
    std::string etherTypeStr = data.substr(12, 2);

    // Convert the EtherType string to a uint16_t using stoi
    uint16_t etherTypeInt = 0;
    try {
        etherTypeInt = static_cast<uint16_t>(std::stoi(etherTypeStr, nullptr, 16));
    } catch (const std::invalid_argument& e) {
        std::cerr << "Invalid EtherType: " << etherTypeStr << std::endl;
        throw std::runtime_error("Invalid EtherType");
    } catch (const std::out_of_range& e) {
        std::cerr << "EtherType out of range: " << etherTypeStr << std::endl;
        throw std::runtime_error("EtherType out of range");
    }

    packet.ethFrame.dest_mac = destMac;
    packet.ethFrame.src_mac = sourceMac;
    assign_ether_type(etherTypeInt,packet.ethFrame.ethertype);
}

void PacketParser::assign_ether_type(uint16_t type, Packet::EtherType& etherType){
    switch (type)
    {
        case 0x0800:
            etherType = Packet::EtherType::IPv4;
            break;
        case 0x86DD:
            etherType = Packet::EtherType::IPv6;
            break;
        case 0x0806:
            etherType = Packet::EtherType::ARP;
            break;
        case 0x8100:
            etherType = Packet::EtherType::VLAN;
            break;
        case 0x8035:
            etherType = Packet::EtherType::RARP;
            break;
        default:
            std::cerr << "Warning: Unsupported EtherType: 0x" << std::hex << type << std::endl;
            etherType = Packet::EtherType::UNKNOWN;
            break;
    }
}
