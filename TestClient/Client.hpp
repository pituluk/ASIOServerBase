#pragma once
#include <algorithm>
#include <array>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <atomic>
#include <concepts>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <variant>
#include <vector>

class TCPClient {
public:
	using PlainSocket = asio::ip::tcp::socket;
	using SslSocket = asio::ssl::stream<asio::ip::tcp::socket>;
	using SocketVariant = std::variant<PlainSocket, SslSocket>;
	asio::io_context::strand strand;

	TCPClient(asio::io_context& io_context);
	TCPClient(asio::io_context& io_context, asio::ssl::context& ssl_context);

	virtual ~TCPClient() = default;
	void connect(const std::string& host, std::uint16_t port);
	bool connected() { return connected_ && !markedToDisconnect; }
	void disconnect();
	void send(std::vector<std::uint8_t> data);
protected:
	virtual void onConnected() {}
	virtual void onDisconnect() {}
	virtual void onData(const std::vector<std::uint8_t>& data) {}
	virtual void onError(const std::error_code& ec, const std::string_view message) {}
private:
	std::atomic<bool> connected_ = false;
	std::atomic<bool> markedToDisconnect = false;
	asio::ip::tcp::resolver resolver_;
	bool use_ssl_;
	std::string host_;
	uint16_t port_;
	SocketVariant socket_;
	std::array<std::uint8_t, 65535> read_buffer_;
	std::deque<std::vector<std::uint8_t>> write_queue_;

	void do_read();
	void do_write();
};