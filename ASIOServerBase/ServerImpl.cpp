#include "ServerImpl.hpp"
#include <iostream>
#include <sstream>
#include <packets/Message.hpp>
#include <packets/Login.hpp>
static std::uint32_t getTimeSeconds()
{
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}


class ChatHandler : public PacketHandler
{
public:
	std::uint8_t getID() { return 1; }
	explicit ChatHandler(Server* owner) : PacketHandler(owner) {}
	void handle(UserConnectionP conn, std::vector<std::uint8_t> data)
	{
		switch (data[1])
		{
		case 1:
			onLogin(conn, std::move(data));
			break;
		case 2:
			onMessage(conn, std::move(data));
			break;
		}
	}
private:
	void onMessage(UserConnectionP connection, std::vector<std::uint8_t> data)
	{
		if (connection->loggedIn)
		{
			SMessage packet(std::move(data));
			std::cout << '[' << connection->id << "] " << connection->name << ":" << packet.message<<'\n';
			SMessage returnPacket;
			returnPacket.write(connection->id, connection->name, packet.message); //should verify message but its only example code
			{
				std::lock_guard lock(owner->conGuard);
				for (auto& conn : owner->connections)
				{
					if (conn->loggedIn)
					{
						conn->write(returnPacket.getBuffer());
					}
				}
			}
		}
		else
		{
			std::cout << "Connection " << connection->id << " sent a message but isnt logged in.\n";
			connection->disconnect();
			return;
		}
	}
	void onLogin(UserConnectionP connection, std::vector<std::uint8_t> data)
	{
		if (connection->loggedIn)
		{
			std::cout << "Connection " << connection->id << " tried to login twice\n";
			connection->disconnect();
			return;
		}
		SLogin packet(std::move(data));
		LOGIN_RESULT result = LOGIN_RESULT::SUCCESS;
		{
			std::lock_guard lock(owner->conGuard);
			for (auto& conn : owner->connections)
			{
				if (conn->name == packet.login)
				{
					result = LOGIN_RESULT::FAILURE;
				}
			}
		}
		if (result != LOGIN_RESULT::SUCCESS)
		{
			std::cout << "Connection " << connection->id << " failed login.\n";
			SLogin returnPacket;
			returnPacket.write(result);
			connection->write(std::move(returnPacket.getBuffer()));
			connection->disconnect();
			return;
		}
		connection->name = packet.login;
		connection->loggedIn = true;
		std::cout << "Connection " << connection->id << " logged in as " << packet.login << '\n';
		SLogin returnPacket;
		returnPacket.write(result);
		connection->write(std::move(returnPacket.getBuffer()));
		SMessage welcomePacket;
		welcomePacket.write(connection->id, connection->name, "has joined.");
		{
			std::lock_guard lock(owner->conGuard);
			for (auto& conn : owner->connections)
			{
				if (conn->loggedIn)
				{
					conn->write(welcomePacket.getBuffer());
				}
			}
		}
		return;
	}
};


Server::Server(const asio::ip::address& ip_, unsigned short port_, bool useProxy, std::size_t threads_) : TCPServer(ip_, port_, useProxy, threads_) {
	addErrorHandler([this](std::error_code ec, std::string_view message, std::optional<UserConnectionP> connection, std::optional<asio::ip::tcp::socket*> socket) -> bool {return this->onError(ec, message, connection, socket); });
	addConnectHandler([this](UserConnectionP connection) -> bool {return this->onConnect(connection); });
	addDisconnectHandler([this](UserConnectionP connection) {this->onDisconnect(connection); });
	addDataHandler([this](UserConnectionP connection, std::vector<std::uint8_t> data) {this->onData(connection, std::move(data)); });
	dispatcher.registerHandler(std::make_unique<ChatHandler>(this));
	start();
}
bool Server::onError(std::error_code ec, std::string_view message, std::optional<UserConnectionP> connection, std::optional<asio::ip::tcp::socket*> socket)
{
	std::stringstream ss;
	ss << "[TCP] Error: " << message << " - " << ec.message() << std::endl;
	if (connection) {
		ss << "Connection ID: " << (*connection)->id << std::endl;
	}
	if (socket) {
		ss << "Socket error occurred." << std::endl;
	}
	std::cout << ss.str();
	return true; // Continue processing
}
bool Server::onConnect(UserConnectionP connection)
{
	std::cout << "[TCP] New connection established. " << connection->realIP << " ID" << connection->id << std::endl;
	connection->connectedOn = getTimeSeconds();
	connection->buffer.reserve(65535);
	return true; // Allow connection
}
void Server::onDisconnect(UserConnectionP connection) {
	std::cout << "Connection ID: " << connection->id << " disconnected." << std::endl;
	if (connection->loggedIn) {
		std::cout << "Connection " << connection->id << " " << connection->name<< " left" << '\n';
		SMessage packet;
		packet.write(connection->id, connection->name, "has left.");
		{
			std::lock_guard lock(conGuard);
			for (auto& conn : connections)
			{
				if (conn->loggedIn)
				{
					conn->write(packet.getBuffer());
				}
			}
		}
	}
}
void Server::onData(UserConnectionP connection, const std::vector<std::uint8_t>& data) {

	auto& buffer = connection->buffer;
	auto& read_offset = connection->read_offset;
	constexpr std::size_t headerSize = 4;
	constexpr std::size_t maxPacketSize = 65535;

	// Append new data to buffer
	buffer.insert(buffer.end(), data.begin(), data.end());

	// Try to parse as many packets as possible
	while (true) {
		// Do we have enough for a header?
		if (buffer.size() < headerSize)
			break;

		// Read length (big-endian)
		std::uint32_t len = (static_cast<std::uint32_t>(buffer[0]) << 24) |
			(static_cast<std::uint32_t>(buffer[1]) << 16) |
			(static_cast<std::uint32_t>(buffer[2]) << 8) |
			(static_cast<std::uint32_t>(buffer[3]));

		// Only disconnect if we have a full header and the length is invalid
		if (len > maxPacketSize) {
			std::cout << "Connection " << connection->id << " sent invalid packet length";
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
		auto handler = dispatcher.getHandler(packet[0]);
		if (!handler)
		{
			std::cout << "Connection " << connection->id << " sent invalid packet!! MAIN: " << packet[0] << '\n';
			connection->disconnect();
			return;
		}
		handler->handle(connection, std::move(packet));
		// Remove parsed packet from buffer
		buffer.erase(buffer.begin(), buffer.begin() + headerSize + len);
	}
}
