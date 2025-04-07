#include "sniffer_engine.hpp"

SnifferEngine::SnifferEngine(SocketManager& manager, Packet::FilterConfig& filter):
    manager(manager),
    filter(filter)
{}

SnifferEngine::~SnifferEngine(){
    stop();
}   

void SnifferEngine::stop(){
    running.store(false);
    cv.notify_all();    //notify all threads to wakeup and check shutdown flag

    if(capturingThread.joinable()) capturingThread.join();
    if(processingThread.joinable()) processingThread.join();
}

void SnifferEngine::start(){
    running.store(true);
    capturingThread = std::thread(&SnifferEngine::capture_packet, this);
    processingThread = std::thread(&SnifferEngine::process_packet, this);
}

void SnifferEngine::capture_packet(){
    std::vector<char> buffer(1024*64);
    size_t size = buffer.size();
    
    while(true)
    {
        if(!running.load()) break;

        size_t bytesReceived = manager.capture_packet(buffer,size);
        if(bytesReceived <= 0){
            std::cout << "Error: No data received or error in capture_packet" << std::endl;
            continue;
        }
        RawPacketData rawPacket = {std::vector<char>(buffer.begin(),buffer.begin()+bytesReceived), bytesReceived};

        {
            //using lock guard as it is simpler and we dont need to wait on cv here
            std::lock_guard<std::mutex> lock(mtx);
            packetQueue.push(std::move(rawPacket));
        }
        cv.notify_one();
    }
}

void SnifferEngine::process_packet()
{
    while(true)
    {
        RawPacketData rawPacket;
        {
            std::unique_lock<std::mutex> lock(mtx);
            
        //waiting on cv releases the lock, hence we need to use unique lock instead of lock guard as lock guard does not allow the use of .lock(), unlock()
            cv.wait(lock, [this] {
                return !packetQueue.empty() || !running.load();
            });

            if(!running.load() && packetQueue.empty()) break;
            if(packetQueue.empty()) continue;

            rawPacket = std::move(packetQueue.front());
            packetQueue.pop();
        }

        try
        {
            Packet packet = PacketParser::parse_packet(rawPacket.data, rawPacket.length);
            if(PacketParser::packet_matches_filter(packet, this->filter))
            {
                PacketPrinter::print_packet(packet);
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << "Processing Error: " << e.what() << '\n';
        }
    }
}
