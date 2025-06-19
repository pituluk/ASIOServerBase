#pragma once
#include "Server.hpp"
#include <map>
class UserConnection : public TCPConnection<UserConnection>
{
public:
    using TCPConnection::TCPConnection;
    std::uint32_t connectedOn = 0;
    bool loggedIn = false;
    std::string name;
    std::vector<std::uint8_t> buffer;
    std::size_t read_offset = 0;
};
using UserConnectionP = std::shared_ptr<UserConnection>;

class Server;
class PacketHandler
{
public:
    Server* owner;
    virtual std::uint8_t getID() { return 0; }
    virtual void handle(UserConnectionP conn, std::vector<std::uint8_t> data) = 0;
    PacketHandler(Server* owner) : owner(owner) {}
private:

};

class PacketHandlerDispatcher {
private:
    std::map<std::uint8_t, std::unique_ptr<PacketHandler>> handlers;

public:
    void registerHandler(std::unique_ptr<PacketHandler> handler) {
        handlers[handler->getID()] = std::move(handler);
    }

    PacketHandler* getHandler(std::uint8_t id) {
        auto it = handlers.find(id);
        return it != handlers.end() ? it->second.get() : nullptr;
    }
};

class Server : public TCPServer<UserConnection>
{

public:
    Server(const asio::ip::address& ip_, unsigned short port_, bool useProxy, std::size_t threads_);
    bool onError(std::error_code ec, std::string_view message, std::optional<UserConnectionP> connection, std::optional<asio::ip::tcp::socket*> socket);
    bool onConnect(UserConnectionP connection);
    void onDisconnect(UserConnectionP connection);
    void onData(UserConnectionP connection, const std::vector<std::uint8_t>& data);
    PacketHandlerDispatcher dispatcher;
};
