#include "ServerImpl.hpp"
#include <iostream>
#include <packets/Login.hpp>
#include <packets/Message.hpp>
#include <sstream>

void UserConnection::onData(const std::vector<std::uint8_t>& data)
{
	auto& buffer = this->buffer;
	auto& read_offset = this->read_offset;
	constexpr std::size_t headerSize = 4;
	constexpr std::size_t maxPacketSize = 65535;
	constexpr std::size_t minPacketSize = 6;
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
		if (len > maxPacketSize || len < minPacketSize) {
			std::cout << "Connection " << this->id << " sent invalid packet length\n";
			this->disconnect();
			return;
		}

		// Do we have the full packet?
		if (buffer.size() < len)
			break;

		// Extract packet from buffer
		std::vector<std::uint8_t> packet(
			buffer.begin() + headerSize,
			buffer.begin() + len
		);
		auto handler = this->dispatcher->getHandler(packet[0]);
		if (!handler)
		{
			std::cout << "Connection " << this->id << " sent invalid packet!! MAIN: " << packet[0] << '\n';
			this->disconnect();
			return;
		}
		handler->handle(std::move(this->self()), std::move(packet));
		// Remove parsed packet from buffer
		buffer.erase(buffer.begin(), buffer.begin() + len);
	}
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
			std::cout << '[' << connection->id << "] " << connection->name << ":" << packet.message << '\n';
			SMessage returnPacket;
			returnPacket.write(connection->id, connection->name, packet.message); //should verify message but its only example code
			{
				std::lock_guard lock(owner->conGuard);
				for (auto& lconn : owner->connections)
				{
					auto conn = std::static_pointer_cast<UserConnection>(lconn);
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
			for (auto& lconn : owner->connections)
			{
				auto conn = std::static_pointer_cast<UserConnection>(lconn);
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
			for (auto& lconn : owner->connections)
			{
				auto conn = std::static_pointer_cast<UserConnection>(lconn);
				if (conn->loggedIn)
				{
					conn->write(welcomePacket.getBuffer());
				}
			}
		}
		return;
	}
};



Server::Server(const asio::ip::address& ip_, unsigned short port_, std::size_t threads_, bool useProxy_) : TCPServer(ip_, port_, std::make_unique<UserConnectionFactory>(&dispatcher), threads_, useProxy_) {
	addErrorHandler([this](std::error_code ec, std::string_view message, IConnectionP connection, asio::ip::tcp::socket* socket) -> bool {return this->onError(ec, message, std::move(std::static_pointer_cast<UserConnection>(connection)), socket); });
	addConnectHandler([this](IConnectionP connection) -> bool {return this->onConnect(std::move(std::static_pointer_cast<UserConnection>(connection))); });
	addDisconnectHandler([this](IConnectionP connection) {this->onDisconnect(std::move(std::static_pointer_cast<UserConnection>(connection))); });
	dispatcher.registerHandler(std::make_unique<ChatHandler>(this));
	start();
}
bool Server::onError(std::error_code ec, std::string_view message, UserConnectionP connection, asio::ip::tcp::socket* socket)
{
	std::stringstream ss;
	ss << "[TCP] Error: " << message << " - " << ec.message() << std::endl;
	if (connection) {
		ss << "Connection ID: " << connection->id << std::endl;
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
	std::cout << "[TCP] Connection ID: " << connection->id << " disconnected." << std::endl;
	if (connection->loggedIn) {
		std::cout << "[TCP] Connection " << connection->id << " " << connection->name << " left" << '\n';
		SMessage packet;
		packet.write(connection->id, connection->name, "has left.");
		{
			std::lock_guard lock(conGuard);
			for (auto& lconn : connections)
			{
				auto conn = std::static_pointer_cast<UserConnection>(lconn);
				if (conn->loggedIn)
				{
					conn->write(packet.getBuffer());
				}
			}
		}
	}
}
