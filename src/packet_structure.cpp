#include "packet_structure.hpp"

const std::string Packet::get_mac_string(const std::array<unsigned char,6>& mac) const
{
    std::stringstream stream;
    
    for(auto& v : mac)
    {
        stream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(v) << ":";
    }

    std::string mAddr = stream.str();
    mAddr.pop_back();

    return mAddr;
}

//Assuming ip in network byte order (big-endian, aka MSB at leftmost, and LSB at rightmost)
const std::string Packet::get_ipv4_string(const uint32_t ip) const
{
    std::stringstream stream;
    //0xFF is basicallly 1111 1111, we ensure that we only extract the 8 bits we need by AND'ing with 0xFF
    stream  << ((ip >> 24) & 0xFF) << '.' 
            << ((ip >> 16) & 0xFF) << '.' 
            << ((ip >> 8) & 0xFF) << '.' 
            << (ip & 0xFF);

    return stream.str();
}

const std::string Packet::get_ipv6_string(const std::array<uint8_t, 16>& ip) const
{
    std::stringstream stream;
    for(auto v : ip)
    {
        stream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(v) << ":";   
    }
    std::string ipAddr = stream.str();
    ipAddr.pop_back();
    return ipAddr;
}
