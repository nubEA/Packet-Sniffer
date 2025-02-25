#ifndef SOCKET_MANAGER_H
#define SOCKET_MANAGER_H

#include <cstdint>      // For uint8_t, size_t
#include <string>       // For std::string
#include <unistd.h>     // For close()
#include <sys/socket.h> // For socket(), bind(), recvfrom()
#include <netinet/in.h> // For htons()
#include <netinet/if_ether.h> // For ETH_P_ALL
#include <sys/ioctl.h>  // For ioctl()
#include <net/if.h>     // For struct ifreq (interface request)
#include <arpa/inet.h>  // For inet_ntoa()
#include <linux/if_packet.h> // For sockaddr_ll (packet socket addressing)
#include <stdexcept>        //For std::runtime_error
#include <iostream>

class SocketManager {
public:
    explicit SocketManager(std::string& interface);
    ~SocketManager();

    bool open_socket();  // Opens a raw socket
    int capture_packet(uint8_t* buffer, size_t buffer_size);  // Captures a raw packet
    bool set_promisc_mode();    //Set promiscous mode on

private:
    int sockfd;         // File descriptor for the socket
    std::string iface;  // Network interface name
};

#endif // SOCKET_MANAGER_H
