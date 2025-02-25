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

class SocketManager {
public:
    explicit SocketManager(const std::string& interface);
    ~SocketManager();

    bool openSocket();  // Opens a raw socket
    int capturePacket(uint8_t* buffer, size_t buffer_size);  // Captures a raw packet
    void closeSocket(); // Closes the socket

private:
    int sockfd;         // File descriptor for the socket
    std::string iface;  // Network interface name
};

#endif // SOCKET_MANAGER_H
