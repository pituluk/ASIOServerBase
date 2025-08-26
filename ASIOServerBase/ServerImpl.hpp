#pragma once
#include "Server.hpp"
#include <chrono>
#include <map>
//TODO split these up into seperate files, but this is just an example so im lazy

static std::uint64_t getTimeSeconds()
{
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

class PacketHandlerDispatcher;
class UserConnection : public TCPConnection
{
public:
	UserConnection(std::uint64_t id, asio::ip::tcp::socket socket, asio::io_context& io_context, asio::ip::address ip, asio::ip::address realIP, PacketHandlerDispatcher* dispatcher) : id(id), dispatcher(dispatcher), TCPConnection(std::move(socket), io_context, ip, realIP)
	{
		this->lowest_layer().set_option(asio::ip::tcp::no_delay(true)); //could be moved into factory I guess
	}
	std::shared_ptr<UserConnection> self()
	{
		return static_pointer_cast<UserConnection>(shared_from_this());
	}
	std::uint64_t id = 0;
	std::uint64_t connectedOn = 0;
	bool loggedIn = false;
	std::string name;
	std::vector<std::uint8_t> buffer;
	std::size_t read_offset = 0;
protected:
	void onData(const std::vector<std::uint8_t>& data) override;
private:
	PacketHandlerDispatcher* dispatcher;
};

using UserConnectionP = std::shared_ptr<UserConnection>;
using IConnectionP = std::shared_ptr<IConnection>;

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
class UserConnectionFactory : public ConnectionFactory
{
public:
	UserConnectionFactory(PacketHandlerDispatcher* dispatcher) : dispatcher(dispatcher) {}
	std::shared_ptr<IConnection> create(asio::ip::tcp::socket socket, asio::io_context& io_context, asio::ip::address ip, asio::ip::address realIP) override {
		std::uint64_t id = idCounter.fetch_add(1);
		auto connection = std::make_shared<UserConnection>(id, std::move(socket), io_context, ip, realIP, dispatcher);
		connection->connectedOn = getTimeSeconds();
		connection->buffer.reserve(65535);
		return connection;
	}
private:
	PacketHandlerDispatcher* dispatcher;
	std::atomic<std::uint64_t> idCounter;
};
class Server : public TCPServer
{

public:
	Server(const asio::ip::address& ip_, unsigned short port_, std::size_t threads = 1, bool useProxy = false);
	bool onError(std::error_code ec, std::string_view message, UserConnectionP connection, asio::ip::tcp::socket* socket);
	bool onConnect(UserConnectionP connection);
	void onDisconnect(UserConnectionP connection);
	PacketHandlerDispatcher dispatcher;
};
