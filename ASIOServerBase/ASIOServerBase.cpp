#include <iostream>
#include "Server.hpp"
#include <chrono>
std::uint32_t getTimeSeconds()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
bool onError(std::error_code ec, std::string_view message, std::optional<std::shared_ptr<TCPConnection>> connection, std::optional<asio::ip::tcp::socket*> socket)
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
struct userData {
    std::uint32_t connectedOn;
    std::string name;
    std::vector<std::uint8_t> buffer;
    size_t read_offset = 0;
};
bool onConnect(std::shared_ptr<TCPConnection> connection)
{
    std::cout << "New connection established. ID" << connection->id << std::endl;
    connection->userData = userData{};
    auto& udr = std::any_cast<userData&>(connection->userData);
    udr.connectedOn = getTimeSeconds();
    udr.name = "User" + std::to_string(connection->id);
    udr.buffer.reserve(65535);
    return true; // Allow connection
}
void onDisconnect(std::shared_ptr<TCPConnection> connection) {
    std::cout << "Connection ID: " << connection->id << " disconnected." << std::endl;
}
void onPacket(const std::vector<std::uint8_t>& packet)
{
    std::string s(packet.begin(), packet.end());
    std::cout << "[1] Parsed packet of size: " << packet.size() << std::endl;
}
void onData(std::shared_ptr<TCPConnection> connection, const std::vector<std::uint8_t>& data) {
    auto& ud = std::any_cast<userData&>(connection->userData);
    auto& buffer = ud.buffer;
    auto& read_offset = ud.read_offset;
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

int main()
{
    asio::ip::tcp::endpoint endpoint(asio::ip::tcp::v4(), 7777);
    TCPServer server(endpoint, false, 8);
    server.addHandler(onError);
    server.addHandler(std::function<bool(std::shared_ptr<TCPConnection>)>(onConnect)); //disgusting, need to fix somehow
    server.addHandler(onDisconnect);
    server.addHandler(onData);
    bool running = true;
    std::cout << "Running on port 7777\n";
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
