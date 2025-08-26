#pragma once
#include "Client.hpp"
class ChatClient : public TCPClient {
public:
	using PacketHandler = std::function<void(std::vector<uint8_t>)>;
	ChatClient(asio::io_context& context);
	void setPacketHandler(PacketHandler handler);
protected:
	virtual void onConnected() override;
	virtual void onDisconnect() override;
	virtual void onData(const std::vector<std::uint8_t>& data) override;
	virtual void onError(const std::error_code& ec, const std::string_view message) override;
	std::vector<std::uint8_t> packet_buffer_;
	std::size_t read_offset_ = 0;
	PacketHandler packet_handler_;
	asio::io_context* context;
};