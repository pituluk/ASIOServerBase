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
	static void read_proxy_header(asio::ip::tcp::socket* s, proxyHeader& header) {
		asio::read(*s, asio::buffer(header.data(), header.size()));
	}
};

class IConnection : public std::enable_shared_from_this<IConnection> {
public:
	virtual ~IConnection() = default;
	virtual void start() = 0;
	virtual void write(std::vector<std::uint8_t> data) = 0;
	virtual void disconnect() = 0;
	virtual void shutdown() = 0;
	virtual void onError(std::error_code ec, std::string_view message) {
		onErrorCb(ec, message);
	}
	virtual void onData(const std::vector<std::uint8_t>& data) { return; }
protected:
	std::function<void(std::error_code ec, std::string_view message)> onErrorCb;
	std::function<void()> onDisconnectCb;
	friend class TCPServer;
};
template<typename Stream>
class BaseConnection : public IConnection {
public:
	BaseConnection(Stream stream_, asio::io_context& io_context, asio::ip::address ip_, asio::ip::address realIP_)
		: stream(std::move(stream_)), strand(io_context), ip(ip_), realIP(realIP_), read_buffer(65535) {
	}

	asio::ip::address ip;
	asio::ip::address realIP;
	asio::io_context::strand strand;
	std::atomic<bool> disconnected = false;

	virtual void start() override {
		this->do_read();
	}

	void write(std::vector<std::uint8_t> data) override {
		auto self = this->shared_from_this();
		if (this->disconnected)
			return;
		asio::post(this->strand, [this, self, data = std::move(data)]() {
			bool write_in_progress = !this->write_queue.empty();
			this->write_queue.push_back(std::move(data));
			if (!write_in_progress) {
				this->do_write();
			}
			});
	}

	void disconnect() override {
		this->disconnected = true;
		auto self = this->shared_from_this();
		asio::dispatch(this->strand, [this, self]() {
			if (!this->write_queue.empty()) return;
			if (this->lowest_layer().is_open()) {
				this->lowest_layer().cancel();
				this->lowest_layer().shutdown(asio::socket_base::shutdown_both);
				this->lowest_layer().close();
			}
			this->onDisconnectCb();
			});
	}

	void shutdown() override {
		if (this->disconnected) return;
		this->disconnected = true;
		auto self = this->shared_from_this();
		asio::dispatch(this->strand, [this, self]() {
			if (this->lowest_layer().is_open()) {
				this->lowest_layer().shutdown(asio::socket_base::shutdown_both);
				this->lowest_layer().close();
			}
			});
	}

	template <typename Func>
	auto executeAfter(std::chrono::steady_clock::duration delay, Func&& func)
		-> std::future<std::invoke_result_t<Func>>
	{
		using ReturnT = std::invoke_result_t<Func>;

		return asio::co_spawn(
			strand.context(),
			asio::bind_executor(strand,
				[delay, func = std::move(func)]() mutable -> asio::awaitable<ReturnT> {
					asio::steady_timer timer{ co_await asio::this_coro::executor };
					timer.expires_after(delay);

					asio::error_code ec;
					co_await timer.async_wait(asio::redirect_error(asio::use_awaitable, ec));

					if (ec)
						throw std::runtime_error(ec.message());

					co_return func();
				}),
			asio::use_future
		);
	}
protected:
	virtual void onData(const std::vector<std::uint8_t>& data) override {}

	Stream& get_stream() { return stream; }
	typename Stream::lowest_layer_type& lowest_layer() { return stream.lowest_layer(); }

private:
	std::deque<std::vector<std::uint8_t>> write_queue;
	std::vector<std::uint8_t> read_buffer;
	Stream stream;

	void do_read() {
		if (this->disconnected) return;

		auto self = this->shared_from_this();
		auto buf = asio::buffer(this->read_buffer.data(), this->read_buffer.size());

		stream.async_read_some(buf,
			asio::bind_executor(this->strand,
				[this, self](const std::error_code& ec, std::size_t length) {
					if (!ec && length > 0) {
						std::vector<std::uint8_t> data(this->read_buffer.begin(), this->read_buffer.begin() + length);
						this->onData(std::move(data));
						this->do_read();
					}
					else if (ec != asio::error::operation_aborted) {
						if (!this->disconnected) this->disconnect();
					}
				}));
	}

	void do_write() {
		auto self = this->shared_from_this();
		asio::async_write(stream,
			asio::buffer(this->write_queue.front()),
			asio::bind_executor(this->strand,
				[this, self](std::error_code ec, std::size_t /*length*/) {
					if (!ec) {
						this->write_queue.pop_front();
						if (!this->write_queue.empty()) {
							this->do_write();
						}
						else if (this->disconnected) {
							this->disconnect();
						}
					}
					else {
						this->onError(ec, "Write failed");
						this->disconnect();
					}
				}));
	}
};

class TCPConnection : public BaseConnection<asio::ip::tcp::socket> {
public:
	using Base = BaseConnection<asio::ip::tcp::socket>;
	TCPConnection(asio::ip::tcp::socket socket_, asio::io_context& io_context, asio::ip::address ip_, asio::ip::address realIP_)
		: Base(std::move(socket_), io_context, ip_, realIP_) {
	}
};

class SSLConnection : public BaseConnection<asio::ssl::stream<asio::ip::tcp::socket>> {
public:
	SSLConnection(asio::ip::tcp::socket socket_, asio::io_context& io_context,
		asio::ssl::context& ssl_context, asio::ip::address ip_, asio::ip::address realIP_)
		: BaseConnection(asio::ssl::stream<asio::ip::tcp::socket>(std::move(socket_), ssl_context),
			io_context, ip_, realIP_) {
	}
	//If you inherit make sure to call start of the class you inherited from.
	void start() override {
		auto self = this->shared_from_this();
		this->get_stream().async_handshake(asio::ssl::stream_base::server,
			asio::bind_executor(this->strand, [this, self](const std::error_code& ec) {
				if (!ec) {
					this->BaseConnection::start();  // proceed to do_read()
				}
				else {
					this->onError(ec, "<SSLConnection::start> SSL Handshake failed");
					this->disconnect();
				}
				}));
	}

};

class ConnectionFactory {
public:
	virtual ~ConnectionFactory() = default;
	virtual std::shared_ptr<IConnection> create(asio::ip::tcp::socket socket, asio::io_context& io_context, asio::ip::address ip, asio::ip::address realIP)
	{
		return std::make_shared<TCPConnection>(std::move(socket), io_context, ip, realIP);
	};
};

struct SSLInitContext
{
	SSLInitContext(const std::vector<std::uint8_t>& chain_file, const std::vector<std::uint8_t>& private_key_file, const std::vector<std::vector<std::uint8_t>>& ca_file, asio::ssl::context::file_format file_format = asio::ssl::context::pem, asio::ssl::context::method ssl_method = asio::ssl::context::tlsv12_server)
		: chain_file(chain_file), private_key_file(private_key_file), ca_file(ca_file), ssl_method(ssl_method), file_format(file_format)
	{
		assert(chain_file.size() > 0);
		assert(private_key_file.size() > 0);
	}
	const asio::ssl::context::method ssl_method;
	const std::vector<std::uint8_t>& chain_file;
	const std::vector<std::uint8_t>& private_key_file;
	const std::vector<std::vector<std::uint8_t>>& ca_file;
	const asio::ssl::context::file_format file_format;
};
class SSLConnectionFactory : public ConnectionFactory {
public:
	SSLConnectionFactory(SSLInitContext sslData) : ssl_ctx(sslData.ssl_method)
	{
		ssl_ctx.use_certificate_chain(asio::buffer(sslData.chain_file));
		ssl_ctx.use_private_key(asio::buffer(sslData.private_key_file), sslData.file_format);
		if (!sslData.ca_file.empty()) {
			for (const auto& cert : sslData.ca_file)
			{
				if (!cert.empty()) {
					ssl_ctx.add_certificate_authority(asio::buffer(cert));
				}
			}
		}
		ssl_ctx.set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert);
	}
	virtual ~SSLConnectionFactory() = default;
	std::shared_ptr<IConnection> create(asio::ip::tcp::socket socket, asio::io_context& io_context, asio::ip::address ip, asio::ip::address realIP) override
	{
		return std::make_shared<SSLConnection>(std::move(socket), io_context, ssl_ctx, ip, realIP);
	};
protected:
	asio::ssl::context ssl_ctx;
};


class TCPServer {
	using ConnectionPtr = std::shared_ptr<IConnection>;
	struct ServerCallbacks {
		std::vector<std::function<bool(std::error_code, std::string_view, ConnectionPtr, asio::ip::tcp::socket*)>> onError;
		std::vector<std::function<bool(ConnectionPtr)>> onConnect;
		std::vector<std::function<void(ConnectionPtr)>> onDisconnect;
	};
public:
	TCPServer(const asio::ip::address& ip_, unsigned short port_, std::unique_ptr<ConnectionFactory> factory = std::make_unique<ConnectionFactory>(), std::size_t threads_ = 1, bool useProxy = false);
	TCPServer(const TCPServer&) = delete;
	TCPServer& operator=(const TCPServer&) = delete;
	~TCPServer();
	void start();
	void stop();
	bool join(ConnectionPtr connection);
	void leave(ConnectionPtr connection);
	void addErrorHandler(std::function<bool(std::error_code, std::string_view, ConnectionPtr, asio::ip::tcp::socket*)> errorCallback);
	void addConnectHandler(std::function<bool(ConnectionPtr)> connectCallback);
	void addDisconnectHandler(std::function<void(ConnectionPtr)> disconnectCallback);


	std::atomic<bool> running = false;
	asio::io_context context;
	asio::ip::address ip;
	unsigned short port;
	std::recursive_mutex conGuard;
	std::vector<ConnectionPtr> connections;
	std::vector<std::thread> threadPool;
	const asio::ip::tcp::endpoint endpoint;
	std::size_t threads = 1;
protected:
	TCPServer() = default;
private:
	bool onError(std::error_code ec, std::string_view message, ConnectionPtr connection = nullptr, asio::ip::tcp::socket* socket = nullptr);
	bool onConnect(ConnectionPtr connection);
	void onDisconnect(ConnectionPtr connection);
	void do_accept();
	std::unique_ptr<ConnectionFactory> connectionFactory;
	asio::executor_work_guard<asio::io_context::executor_type> workGuard;
	std::shared_mutex handlerGuard;
	ServerCallbacks callbacks;
	asio::io_context::strand serverStrand;
	asio::ip::tcp::acceptor acceptor;
	bool proxied = false;
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