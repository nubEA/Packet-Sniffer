#ifndef SNIFFER_ENGINE_HPP
#define SNIFFER_ENGINE_HPP

#include <mutex>
#include <queue>
#include <thread>
#include <iostream>
#include <atomic>
#include <condition_variable>
#include "socket_manager.hpp"
#include "packet_structure.hpp"
#include "packet_parser.hpp"
#include "packet_printer.hpp"

class SnifferEngine{
    public:
        struct RawPacketData
        {
            std::vector<char> data;
            size_t length;
        };

        SnifferEngine(SocketManager& manager, Packet::FilterConfig& filter);
        ~SnifferEngine();

        void start();
        void stop();
    
    private:
        SocketManager& manager;
        Packet::FilterConfig filter;

        std::thread processingThread;
        std::thread capturingThread;
        std::mutex mtx;
        std::queue<RawPacketData> packetQueue;
        std::condition_variable cv;
        std::atomic<bool> running{false};

        void capture_packet();
        void process_packet();

};

#endif