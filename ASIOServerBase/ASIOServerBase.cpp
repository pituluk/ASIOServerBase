#include <iostream>
#include "ServerImpl.hpp"
#include <chrono>
std::uint32_t getTimeSeconds()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
bool onError(std::error_code ec, std::string_view message, std::optional<std::shared_ptr<Connection>> connection, std::optional<asio::ip::tcp::socket*> socket)
{
    std::cout << "Error: " << message << " - " << ec.message() << std::endl;
    if (connection) {
        std::cout << "Connection ID: " << (*connection)->id << std::endl;
    }
    if (socket) {
        std::cout << "Socket error occurred." << std::endl;
    }
    return true; // Continue processing
}
bool onConnect(std::shared_ptr<Connection> connection)
{
    std::cout << "New connection established. "<<connection->realIP<< " ID" << connection->id << std::endl;
    connection->userData.connectedOn = getTimeSeconds();
    connection->userData.name = "User" + std::to_string(connection->id);
    connection->userData.buffer.reserve(65535);
    return true; // Allow connection
}
void onDisconnect(std::shared_ptr<Connection> connection) {
    std::cout << "Connection ID: " << connection->id << " disconnected." << std::endl;
}
void onPacket(const std::vector<std::uint8_t>& packet)
{
    std::string s(packet.begin(), packet.end());
    std::cout << "[1] Parsed packet of size: " << packet.size() << std::endl;
}
void onData(std::shared_ptr<Connection> connection, const std::vector<std::uint8_t>& data) {
    
    auto& buffer = connection->userData.buffer;
    auto& read_offset = connection->userData.read_offset;
    constexpr size_t headerSize = 4;
    constexpr size_t maxPacketSize = 65535;

    // Append new data to buffer
    buffer.insert(buffer.end(), data.begin(), data.end());

    // Try to parse as many packets as possible
    while (true) {
        // Do we have enough for a header?
        if (buffer.size() < headerSize)
            break;

        // Read length (big-endian)
        std::uint32_t len = (static_cast<uint32_t>(buffer[0]) << 24) |
            (static_cast<uint32_t>(buffer[1]) << 16) |
            (static_cast<uint32_t>(buffer[2]) << 8) |
            (static_cast<uint32_t>(buffer[3]));

        // Only disconnect if we have a full header and the length is invalid
        if (len > maxPacketSize) {
                connection->disconnect();
                return;
        }

        // Do we have the full packet?
        if (buffer.size() < headerSize + len)
            break;

        // Extract packet from buffer
        std::vector<std::uint8_t> packet(
            buffer.begin() + headerSize,
            buffer.begin() + headerSize + len
        );
        onPacket(packet);

        // Remove parsed packet from buffer
        buffer.erase(buffer.begin(), buffer.begin() + headerSize + len);
    }
}
void udpData(UDPServer& server,const asio::ip::udp::endpoint& remote, const std::vector<std::uint8_t>& data)
{
    std::string s(data.begin(), data.end());
    std::cout << "[UDP] Received data from:" << remote.address().to_string() << ":" << remote.port() << " TID:" << std::this_thread::get_id() <<" Size:"<<data.size() << "\nMessage: " << s << std::endl;
    std::vector<std::uint8_t> resend(s.begin(), s.end());
    server.send(remote, resend);
}
int main()
{
    Server server(asio::ip::make_address("0.0.0.0"),7777, false, 8);
    server.addHandler(onError);
    server.addHandler(std::function<bool(std::shared_ptr<Connection>)>(onConnect)); //disgusting, need to fix somehow
    server.addHandler(onDisconnect);
    server.addHandler(onData);
    bool running = true;
    std::cout << "[TCP] Running on " << server.ip << ":" << server.port << std::endl;
    
    UDPServer server2(asio::ip::make_address("0.0.0.0"),7777, 8);
    server2.addHandler(udpData);
    std::cout << "[UDP] Running on " << server2.ip << ":" << server2.port << std::endl;
    while (running == true)
    {
        std::string input;
        std::cin >> input;
        if (input == "stop" || input == "s")
        {
            running = false;
        }
    }
}
