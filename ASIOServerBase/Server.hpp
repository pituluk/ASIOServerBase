#pragma once
#include <third_party/asio.hpp>
#include <cstdint>
#include <any>
#include <vector>
#include <array>
#include <deque>
#include <shared_mutex>
#include <atomic>
#include <thread>
#include <mutex>
#include <optional>
#include <algorithm>
#include <variant>
#include <memory>
#include <concepts>
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


template <typename Derived>
struct ConnectionCallbacks {
	std::function<void(std::error_code, std::string_view, std::shared_ptr<Derived> connection)> onError;
	std::function<void(std::shared_ptr<Derived>)> onDisconnect;
	std::function<void(std::shared_ptr<Derived>, std::vector<std::uint8_t>)> onData;
};

template<typename Derived>
class TCPConnection : public std::enable_shared_from_this<Derived> {
	template <typename T>
	friend class TCPServer;
public:
	TCPConnection(std::uint64_t id_, asio::ip::tcp::socket socket_, asio::ip::address ip_, asio::ip::address realIP_, asio::io_context& io_context);
	TCPConnection(const TCPConnection&) = delete;
	TCPConnection& operator=(const TCPConnection&) = delete;
	std::uint64_t id;
	asio::ip::address ip;
	asio::ip::address realIP;
	asio::io_context::strand strand;
	void start();
	void write(std::vector<std::uint8_t> data);
	void disconnect();
	void shutdown();
	std::shared_ptr<Derived> self() {
		return this->shared_from_this();
	}
protected:
	void setCallbacks(ConnectionCallbacks<Derived> cb) { callbacks = std::move(cb); }
	ConnectionCallbacks<Derived> callbacks;
	TCPConnection() = default;
private:
	void onDisconnect() {
		if (callbacks.onDisconnect)
		{
			callbacks.onDisconnect(self());
		}
	}
	void onError(std::error_code ec, std::string_view message)
	{
		if (callbacks.onError)
		{
			callbacks.onError(ec, message, self());
		}
	}
	void onData(std::vector<std::uint8_t> data)
	{
		if (callbacks.onData)
		{
			callbacks.onData(self(), std::move(data));
		}
	}
	std::atomic<bool> disconnected = false;
	asio::ip::tcp::socket socket;
	void do_read();
	void do_write();
	std::deque<std::vector<std::uint8_t>> write_queue;
	std::vector<std::uint8_t> read_buffer;
};



template<typename ConnectionType>
class TCPServer {
	static_assert(std::is_base_of_v<TCPConnection<ConnectionType>, ConnectionType>, "ConnectionType must derive from TCPConnection");
public:
	using ConnectionPtr = std::shared_ptr<ConnectionType>;
	TCPServer(const asio::ip::address& ip_, unsigned short port_, bool useProxy = false, std::size_t threads_ = 1);
	TCPServer(const TCPServer&) = delete;
	TCPServer& operator=(const TCPServer&) = delete;
	~TCPServer();


	struct ServerCallbacks {
		std::vector<std::function<bool(std::error_code, std::string_view, std::optional<ConnectionPtr>, std::optional<asio::ip::tcp::socket*>)>> onError;
		std::vector<std::function<bool(ConnectionPtr)>> onConnect;
		std::vector<std::function<void(ConnectionPtr)>> onDisconnect;
		std::vector<std::function<void(ConnectionPtr, const std::vector<std::uint8_t>&)>> onData;
	};
	void start();
	void stop();
	bool join(ConnectionPtr connection);
	void leave(ConnectionPtr connection);
	void addErrorHandler(std::function<bool(std::error_code, std::string_view, std::optional<ConnectionPtr>, std::optional<asio::ip::tcp::socket*>)> errorCallback);
	void addConnectHandler(std::function<bool(ConnectionPtr)> connectCallback);
	void addDisconnectHandler(std::function<void(ConnectionPtr)> disconnectCallback);
	void addDataHandler(std::function<void(ConnectionPtr, const std::vector<std::uint8_t>&)> dataCallback);

	std::atomic<bool> running = false;
	asio::io_context context;
	asio::ip::address ip;
	unsigned short port;
	std::recursive_mutex conGuard;
	std::vector<ConnectionPtr> connections;
	std::vector<std::thread> threadPool;
	const asio::ip::tcp::endpoint endpoint;
protected:
	TCPServer() = default;
private:
	asio::executor_work_guard<asio::io_context::executor_type> workGuard;
	std::shared_mutex handlerGuard;
	ServerCallbacks callbacks;
	bool onError(std::error_code ec, std::string_view message = "", std::optional<ConnectionPtr> connection = std::nullopt, std::optional<asio::ip::tcp::socket*> socket = std::nullopt);
	bool onConnect(ConnectionPtr connection);
	void onDisconnect(ConnectionPtr connection);
	void onData(ConnectionPtr connection, const std::vector<std::uint8_t> data);
	std::atomic<std::uint64_t> idCounter = 0;
	void do_accept();
	asio::io_context::strand serverStrand;
	asio::ip::tcp::acceptor acceptor;
	bool proxied = false;
	std::size_t threads = 1;
	void read_proxy_header(asio::ip::tcp::socket* s, proxyHeader& header);
};

// --- TCPConnection implementation ---
template<typename Derived>
TCPConnection<Derived>::TCPConnection(std::uint64_t id_, asio::ip::tcp::socket socket_, asio::ip::address ip_, asio::ip::address realIP_, asio::io_context& io_context)
	: id(id_), socket(std::move(socket_)), ip(ip_), realIP(realIP_), strand(io_context), read_buffer(65535) {
}
template<typename Derived>
void TCPConnection<Derived>::start() {
	do_read();
}
template<typename Derived>
void TCPConnection<Derived>::write(std::vector<std::uint8_t> data) {
	auto self = this->shared_from_this();
	if (disconnected)
		return;
	asio::post(strand, [this, self, data = std::move(data)]() {
		bool write_in_progress = !write_queue.empty();
		write_queue.push_back(std::move(data));
		if (!write_in_progress) {
			do_write();
		}
		});
}
template<typename Derived>
void TCPConnection<Derived>::disconnect() {
	disconnected = true;
	auto self = this->shared_from_this();
	asio::post(strand, [this, self]() {
		if (!write_queue.empty()) {
			return;
		}
		if (socket.is_open()) {
			socket.shutdown(asio::socket_base::shutdown_both);
			socket.close();
		}
		onDisconnect();
		});
}
template<typename Derived>
void TCPConnection<Derived>::shutdown() {
	if (disconnected)
	{
		return;
	}
	disconnected = true;
	auto self = this->shared_from_this();
	asio::dispatch(strand, [this, self]() {
		if (socket.is_open()) {
			socket.shutdown(asio::socket_base::shutdown_both);
			socket.close();
		}
		});
	//we dont call onDisconnect because shutdown is used if connection didnt fire onConnect
}
template<typename Derived>
void TCPConnection<Derived>::do_read() {
	if (disconnected)
	{
		return;
	}
	auto self = this->shared_from_this();

	auto buf = asio::buffer(this->read_buffer.data(), this->read_buffer.size());
	socket.async_read_some(
		buf,
		asio::bind_executor(strand, [this, self](const std::error_code& ec, std::size_t length) {
			if (!ec && length > 0) {
				std::vector<std::uint8_t> data(read_buffer.begin(), read_buffer.begin() + length);
				onData(std::move(data));
				do_read();
			}
			else if (ec != asio::error::operation_aborted) {
				if (!disconnected) {
					disconnect();
				}
			}
			})
	);
}
template<typename Derived>
void TCPConnection<Derived>::do_write() {
	auto self = this->shared_from_this();
	asio::async_write(
		socket,
		asio::buffer(write_queue.front()),
		asio::bind_executor(strand, [this, self](std::error_code ec, std::size_t /*length*/) {
			if (!ec) {
				write_queue.pop_front();
				if (!write_queue.empty()) {
					do_write();
				}
				else if (disconnected)
				{
					disconnect();
				}
			}
			else {
				onError(ec, "Write failed");
				disconnect();
			}
			})
	);
}

// --- TCPServer implementation ---
template<typename ConnectionType>
TCPServer<ConnectionType>::TCPServer(const asio::ip::address& ip_, unsigned short port_, bool useProxy, std::size_t threads_)
	: ip(ip_), port(port_), acceptor(context, asio::ip::tcp::endpoint(ip_, port_)), threads(threads_), proxied(useProxy), workGuard(asio::make_work_guard(context)), serverStrand(context) {
}


template<typename ConnectionType>
TCPServer<ConnectionType>::~TCPServer() {
	stop();
	for (auto& thread : threadPool) {
		if (thread.joinable()) {
			thread.join();
		}
	}
	running = false;
	running.notify_all();
}

template<typename ConnectionType>
void TCPServer<ConnectionType>::start()
{
	if (running)
	{
		return;
	}
	for (std::size_t i = 0; i < threads; i++) {
		threadPool.emplace_back([this]() {
			try {
				this->context.run();
			}
			catch (const std::system_error& ex)
			{
				onError(ex.code(), std::string("context.run(): ") + ex.what());
			}
			catch (const std::exception& ex)
			{
				onError(std::make_error_code(std::errc::interrupted), std::string("context.run(): ") + ex.what());
			}
			catch (...)
			{
				onError(std::make_error_code(std::errc::invalid_argument), "Unknown error from context.run()");
			}
			});
	}
	do_accept();
	running = true;
}
template<typename ConnectionType>
void TCPServer<ConnectionType>::stop() {
	if (!running)
	{
		return;
	}
	{
		std::unique_lock lock(conGuard);
		for (auto connection : connections) {
			connection->shutdown();
		}
	}
	std::promise<void> shutdownDone;
	serverStrand.dispatch([this, &shutdownDone] {
		acceptor.close();
		workGuard.reset();
		context.stop();
		shutdownDone.set_value();
		});
	shutdownDone.get_future().wait();
	running = false;
	running.notify_all();
}
template<typename ConnectionType>
bool TCPServer<ConnectionType>::join(ConnectionPtr connection) {
	if (onConnect(connection)) {
		std::lock_guard<std::recursive_mutex> lock(conGuard);
		connections.push_back(connection);
		return true;
	}
	else {
		return false;
	}
}
template<typename ConnectionType>
void TCPServer<ConnectionType>::leave(ConnectionPtr connection) {
	std::lock_guard<std::recursive_mutex> lock(conGuard);
	auto it = std::find(connections.begin(), connections.end(), connection);
	if (it != connections.end()) {
		connections.erase(it);
	}
}
template<typename ConnectionType>
void TCPServer<ConnectionType>::addErrorHandler(std::function<bool(std::error_code, std::string_view, std::optional<ConnectionPtr>, std::optional<asio::ip::tcp::socket*>)> errorCallback) {
	std::unique_lock lock(handlerGuard);
	callbacks.onError.push_back(errorCallback);
}
template<typename ConnectionType>
void TCPServer<ConnectionType>::addConnectHandler(std::function<bool(ConnectionPtr)> connectCallback) {
	std::unique_lock lock(handlerGuard);
	callbacks.onConnect.push_back(connectCallback);
}
template<typename ConnectionType>
void TCPServer<ConnectionType>::addDisconnectHandler(std::function<void(ConnectionPtr)> disconnectCallback) {
	std::unique_lock lock(handlerGuard);
	callbacks.onDisconnect.push_back(disconnectCallback);
}
template<typename ConnectionType>
void TCPServer<ConnectionType>::addDataHandler(std::function<void(ConnectionPtr, const std::vector<std::uint8_t>&)> dataCallback) {
	std::unique_lock lock(handlerGuard);
	callbacks.onData.push_back(dataCallback);
}
template<typename ConnectionType>
bool TCPServer<ConnectionType>::onError(std::error_code ec, std::string_view message, std::optional<ConnectionPtr> connection, std::optional<asio::ip::tcp::socket*> socket) {
	std::shared_lock lock(handlerGuard);
	bool ret = true;
	for (const auto& callback : callbacks.onError) {
		if (!callback(ec, message, connection, socket)) {
			ret = false;
		}
	}
	return ret;
}
template<typename ConnectionType>
bool TCPServer<ConnectionType>::onConnect(ConnectionPtr connection) {
	std::shared_lock lock(handlerGuard);
	for (const auto& callback : callbacks.onConnect) {
		if (!callback(connection)) {
			return false;
		}
	}
	return true;
}
template<typename ConnectionType>
void TCPServer<ConnectionType>::onDisconnect(ConnectionPtr connection) {
	leave(connection);
	std::shared_lock lock(handlerGuard);
	for (const auto& callback : callbacks.onDisconnect) {
		callback(connection);
	}
}
template<typename ConnectionType>
void TCPServer<ConnectionType>::onData(ConnectionPtr connection, const std::vector<std::uint8_t> data) {
	std::shared_lock lock(handlerGuard);
	for (const auto& callback : callbacks.onData) {
		callback(connection, data); //callback takes const reference to data
	}
}
template<typename ConnectionType>
void TCPServer<ConnectionType>::do_accept() {
	serverStrand.post([this] {
		acceptor.async_accept(
			[this](std::error_code ec, asio::ip::tcp::socket socket) {
				if (!ec) {
					std::uint64_t connectionID = idCounter.fetch_add(1);
					asio::ip::address ip = socket.remote_endpoint().address();
					asio::ip::address realIP;
					if (!proxied) {
						realIP = ip;
					}
					else {
						proxyHeader proxyheader;
						read_proxy_header(&socket, proxyheader);
						auto status = proxyheader.decode_header();
						if (status == proxyHeaderParseStatus::SuccessProxy) {
							realIP = asio::ip::make_address_v4(proxyheader.src_addr);
						}
						else {
							onError(std::make_error_code(std::errc::invalid_argument), "Proxy header failed " + std::to_string(static_cast<int>(status)), std::nullopt, &socket);
							return;
						}
					}
					ConnectionPtr conn = std::make_shared<ConnectionType>(connectionID, std::move(socket), ip, realIP, context);
					conn->setCallbacks({
						.onError = [this](std::error_code ec, std::string_view message, ConnectionPtr connection) { this->onError(ec,message,connection); },
						.onDisconnect = [this](ConnectionPtr connection) {this->onDisconnect(connection); },
						.onData = [this](ConnectionPtr connection, std::vector<std::uint8_t> data) { this->onData(connection,std::move(data)); }
						});
					bool allowed = join(conn);
					if (allowed) {
						conn->start();
					}
					else {
						onError(std::make_error_code(std::errc::permission_denied), "Connection not allowed", conn, std::nullopt);
						conn->shutdown();
					}
				}
				else {
					onError(ec, "Accept failed", std::nullopt, &socket);
				}
				do_accept();
			});
		});
}

template<typename ConnectionType>
void TCPServer<ConnectionType>::read_proxy_header(asio::ip::tcp::socket* s, proxyHeader& header) {
	asio::read(*s, asio::buffer(header.data(), header.size()));
}

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
	asio::io_context context;
	asio::executor_work_guard<asio::io_context::executor_type> workGuard;
	void start_receive();
	std::shared_mutex handlerGuard;
	std::vector<std::function<void(UDPServer&, const asio::ip::udp::endpoint&, const std::vector<std::uint8_t>&)>> dataHandlers;
	std::vector<std::uint8_t> recvBuffer;
	asio::ip::udp::socket socket;
	asio::ip::udp::endpoint remoteEndpoint;
	std::size_t threads = 1;
};