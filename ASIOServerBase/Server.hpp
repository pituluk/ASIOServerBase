#pragma once
#include "asio.hpp"
#include <cstdint>
#include <any>
#include <vector>
#include <array>
#include <deque>
#include <shared_mutex>
#include <optional>
#include <atomic>
#include <thread>
#include <mutex>
#include <algorithm>

enum class proxyHeaderParseStatus {
	SuccessProxy,
	FailedSignature,
	FailedVersion,
	FailedCommand,
	HealthCheck,
	FailedFamily,
	FailedProtocol,
	FailedLen
};

enum class ProtocolType { TCP = 1, UDP = 2 };
enum class FamilyType { IPv4 = 1, IPv6 = 2 };
//todo: implement ipv6, udpserver
class proxyHeader {
private:
	static constexpr std::array<unsigned char, 12> expectedSignature = { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };
	std::vector<uint8_t> bytes;
	static constexpr std::size_t bsize = 28;
	ProtocolType protocolType;
	FamilyType familyType;
public:
	proxyHeader(ProtocolType t = ProtocolType::TCP, FamilyType f = FamilyType::IPv4) : bytes(28), protocolType(t), familyType(f) {}

	std::uint8_t protocolVersion = UINT8_MAX;
	std::uint8_t family = UINT8_MAX;
	std::uint16_t len = UINT16_MAX;
	std::uint32_t src_addr = UINT32_MAX;
	std::uint32_t dst_addr = UINT32_MAX;
	std::uint16_t src_port = UINT16_MAX;
	std::uint16_t dst_port = UINT16_MAX;

	size_t size();
	char* data();
	void clear();
	proxyHeaderParseStatus decode_header();
};

// Forward declaration
class TCPServer;

class TCPConnection : public std::enable_shared_from_this<TCPConnection> {
	friend class TCPServer;
public:
	TCPConnection(std::uint64_t id_, asio::ip::tcp::socket socket_, TCPServer* server_, asio::ip::address ip_, asio::ip::address realIP_, asio::io_context& io_context);
	std::uint64_t id;
	asio::ip::address ip;
	asio::ip::address realIP;
	asio::io_context::strand strand;
	std::any userData;
	void start();
	void write(std::vector<std::uint8_t>& data);
	void disconnect();
	void shutdown();
private:
	std::atomic<bool> disconnected = false;
	asio::ip::tcp::socket socket;
	TCPServer* server;
	void do_read();
	void do_write();
	std::deque<std::vector<std::uint8_t>> write_queue;
	std::vector<std::uint8_t> read_buffer;
};

class TCPServer {
	friend class TCPConnection;
public:
	std::atomic<bool> running = false;
	asio::ip::address ip;
	unsigned short port;
	std::recursive_mutex conGuard;
	std::vector<std::shared_ptr<TCPConnection>> connections;
	std::vector<std::thread> threadPool;
	const asio::ip::tcp::endpoint endpoint;
	TCPServer(const asio::ip::address& ip_, unsigned short port_, bool useProxy = false, std::size_t threads_ = 1);
	~TCPServer();
	void stop();
	bool join(std::shared_ptr<TCPConnection> connection);
	void leave(std::shared_ptr<TCPConnection> connection);
	void addHandler(std::function<bool(std::error_code, std::string_view, std::optional<std::shared_ptr<TCPConnection>>, std::optional<asio::ip::tcp::socket*>)> errorCallback);
	void addHandler(std::function<bool(std::shared_ptr<TCPConnection>)> connectCallback);
	void addHandler(std::function<void(std::shared_ptr<TCPConnection>)> disconnectCallback);
	void addHandler(std::function<void(std::shared_ptr<TCPConnection>, const std::vector<std::uint8_t>&)> dataCallback);
private:
	asio::executor_work_guard<asio::io_context::executor_type> workGuard;
	std::shared_mutex handlerGuard;
	std::vector<std::function<bool(std::error_code, std::string_view, std::optional<std::shared_ptr<TCPConnection>>, std::optional<asio::ip::tcp::socket*>)>> errorCallbacks;
	std::vector<std::function<bool(std::shared_ptr<TCPConnection>)>> connectCallbacks;
	std::vector<std::function<void(std::shared_ptr<TCPConnection>)>> disconnectCallbacks;
	std::vector<std::function<void(std::shared_ptr<TCPConnection>, const std::vector<std::uint8_t>&)>> dataCallbacks;
	bool onError(std::error_code ec, std::string_view message = "", std::optional<std::shared_ptr<TCPConnection>> connection = std::nullopt, std::optional<asio::ip::tcp::socket*> socket = std::nullopt);
	bool onConnect(std::shared_ptr<TCPConnection> connection);
	void onDisconnect(std::shared_ptr<TCPConnection> connection);
	void onData(std::shared_ptr<TCPConnection> connection, const std::vector<std::uint8_t> data);
	std::atomic<std::uint64_t> idCounter = 0;
	void do_accept();
	asio::io_context context;
	asio::ip::tcp::acceptor acceptor;
	bool proxied = false;
	std::size_t threads = 1;
	void read_proxy_header(asio::ip::tcp::socket* s, proxyHeader& header);
};


// UDP


class UDPServer {

public:
	asio::ip::address ip;
	unsigned short port;
	std::vector<std::thread> threadPool;
	UDPServer(const asio::ip::address& ip_, unsigned short port_, std::size_t threads_ = 1);

	~UDPServer();
	void send(const asio::ip::udp::endpoint& to, std::vector<uint8_t>& data);
	void addHandler(std::function<void(UDPServer&, const asio::ip::udp::endpoint&, const std::vector<std::uint8_t>&)> handler);

private:
	void start_receive();
	std::shared_mutex handlerGuard;
	std::vector<std::function<void(UDPServer&, const asio::ip::udp::endpoint&, const std::vector<std::uint8_t>&)>> dataHandlers;
	std::vector<std::uint8_t> recvBuffer;
	asio::io_context context;
	asio::ip::udp::socket socket;
	asio::ip::udp::endpoint remoteEndpoint;
	std::size_t threads = 1;
};