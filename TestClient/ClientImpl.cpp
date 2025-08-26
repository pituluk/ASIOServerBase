#include "ClientImpl.hpp"
#include <iostream>
ChatClient::ChatClient(asio::io_context& context) : TCPClient(context), context(&context)
{
}
void ChatClient::setPacketHandler(PacketHandler handler) {
	packet_handler_ = std::move(handler);
}
void ChatClient::onConnected() //this is stupid but I dont wanna block io_context or worry about lifetime
{
	std::cout << "Client connected!\n";
}
void ChatClient::onDisconnect()
{
	context->stop();
}
void ChatClient::onError(const std::error_code& ec, std::string_view message)
{
	std::cout << "ChatClient::onError " << ec.message() << " " << message << '\n';
}

void ChatClient::onData(const std::vector<std::uint8_t>& data)
{
	auto& buffer = packet_buffer_;
	auto& read_offset = read_offset_;
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

		std::uint32_t len = (static_cast<std::uint32_t>(buffer[0]) << 24) |
			(static_cast<std::uint32_t>(buffer[1]) << 16) |
			(static_cast<std::uint32_t>(buffer[2]) << 8) |
			(static_cast<std::uint32_t>(buffer[3]));


		// Only disconnect if we have a full header and the length is invalid
		if (len > maxPacketSize || len < minPacketSize) {
			std::cout << "Chat server sent invalid packet length: " << len << '\n';
			disconnect();
			return;
		}

		// Do we have the full packet?
		if (buffer.size() < len - headerSize)
			break;

		// Extract packet from buffer
		std::vector<std::uint8_t> packet(
			buffer.begin() + headerSize,
			buffer.begin() + len
		);
		if (packet_handler_) {
			packet_handler_(std::move(packet));
		}

		// Remove parsed packet from buffer
		buffer.erase(buffer.begin(), buffer.begin() + len);
	}
}