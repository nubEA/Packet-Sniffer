#include "socket_manager.hpp"

SocketManager::SocketManager(std::string& interfaceName)
{
    sockfd = -1;    
    iface = interfaceName;

    if(!open_socket()) throw std::runtime_error("Error in opening and setting up the socket");

}

SocketManager::~SocketManager(){
    if(sockfd > 0) close(sockfd);
    std::cout << "Closing Socket....\n";
}

bool SocketManager::open_socket(){
    //Since we want to capture all packets, we use ETH_P_ALL macro to tell kernel to let us capture all ethernet frames
    //We wont be able to see outgoing packets using raw socketss
    sockfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(sockfd < 0){
        std::cout << "Error in opening the socket\n";
        return false;
    }

    //since we are dealiing with AF_PACKET we are not using setsockopt and SO_BINDTODEVICE as it is not supported
    //sockaddr_in identifies an IP address and port for a packet
    //Similarly sockaddr_ll identifies a link-layer address and port. 
    //For raw AF_PACKET sockets addr means a network interface from which the socket will receive packets
    //if_nametoindex converts interface name to int
    struct sockaddr_ll socket_addr{};
    
    if((socket_addr.sll_ifindex = if_nametoindex(iface.c_str())) == 0){
        std::cout << "Error in converting interface name to index\n";
        return false;
    }
    socket_addr.sll_family = AF_PACKET;
    socket_addr.sll_protocol = htons(ETH_P_ALL);
    
    if(bind(sockfd,(struct sockaddr*) &socket_addr,sizeof(socket_addr)) != 0){
        std::cout << "Error binding to an interface\n";
        return false;
    }

    if(!set_promisc_mode()){
        std::cout << "Error setting promiscuous mode\n";
        return false;
    }

    return true;
}

bool SocketManager::set_promisc_mode()
{   

    //Using setsockopt over ioctl to set promisc mode, since it is more socket specific and modern approach
    //when we close the socket the promisc mode will automatically turned off, whereas using ioctl turns it on globally.
    struct packet_mreq mreq{};
    if((mreq.mr_ifindex = if_nametoindex(iface.c_str())) == 0)
    {
        std::cout << "Error converting iface to index in set_promisc\n";
        return false;
    }
    mreq.mr_type = PACKET_MR_PROMISC;   
    
    //Using SOL_PACKET to specify we need to set something at the packet level
    if(setsockopt(sockfd,SOL_PACKET,PACKET_ADD_MEMBERSHIP,&mreq,sizeof(mreq)) < 0){
        std::cout << "Error setting promiscous mode on\n";
        return false;
    }
    return true;
}

int SocketManager::capture_packet(std::vector<char>& buffer, size_t buffer_size){
    //We pass in sockaddr to get metadata/info about the sender like MAC addr in this case (since using _ll, if we used _in we get IP etc)
    struct sockaddr_ll sockaddr{};
    socklen_t len = sizeof(sockaddr);

    int bytesReceived = recvfrom(sockfd,buffer.data(),buffer_size,0,(struct sockaddr*)&sockaddr,&len);
    if(bytesReceived == -1) std::cout << "Error receving packets\n";

    return bytesReceived;
}

