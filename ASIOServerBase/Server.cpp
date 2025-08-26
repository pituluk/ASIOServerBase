#include "Server.hpp"
#include <algorithm>
#include <iostream>
#include <ranges>
// --- proxyHeader implementation 

size_t proxyHeader::size() { return bsize; }
char* proxyHeader::data() { return (char*)bytes.data(); }
void proxyHeader::clear() { bytes.clear(); }
proxyHeaderParseStatus proxyHeader::decode_header() {
	bool isGoodHeader = std::ranges::equal(expectedSignature.begin(), expectedSignature.end(), bytes.begin(), bytes.begin() + expectedSignature.size());
	if (!isGoodHeader) return proxyHeaderParseStatus::FailedSignature;
	protocolVersion = bytes[expectedSignature.size()];
	uint8_t version = protocolVersion >> 4;
	uint8_t command = protocolVersion & 0xF;
	if (version != 2) return proxyHeaderParseStatus::FailedVersion;
	if (command == 0) return proxyHeaderParseStatus::HealthCheck;
	else if (command != 1) return proxyHeaderParseStatus::FailedCommand;
	family = bytes[expectedSignature.size() + 1];
	uint8_t adrFamily = family >> 4;
	uint8_t protocol = family & 0xF;
	if (adrFamily != static_cast<uint8_t>(familyType)) return proxyHeaderParseStatus::FailedFamily;
	if (protocol != static_cast<uint8_t>(protocolType)) return proxyHeaderParseStatus::FailedProtocol;
	len = bytes[expectedSignature.size() + 2] << 8 | bytes[expectedSignature.size() + 3];
	src_addr = bytes[expectedSignature.size() + 4] << 24 | bytes[expectedSignature.size() + 5] << 16 |
		bytes[expectedSignature.size() + 6] << 8 | bytes[expectedSignature.size() + 7];
	dst_addr = bytes[expectedSignature.size() + 8] << 24 | bytes[expectedSignature.size() + 9] << 16 |
		bytes[expectedSignature.size() + 10] << 8 | bytes[expectedSignature.size() + 11];
	if (len == 12) {
		src_port = bytes[expectedSignature.size() + 12] << 8 | bytes[expectedSignature.size() + 13];
		dst_port = bytes[expectedSignature.size() + 14] << 8 | bytes[expectedSignature.size() + 15];
	}
	else {
		return proxyHeaderParseStatus::FailedLen;
	}
	return proxyHeaderParseStatus::SuccessProxy;
}


TCPServer::TCPServer(const asio::ip::address& ip_, unsigned short port_, std::unique_ptr<ConnectionFactory> factory, std::size_t threads_, bool useProxy)
	: ip(ip_), port(port_), acceptor(context, asio::ip::tcp::endpoint(ip_, port_)), threads(threads_), proxied(useProxy), workGuard(asio::make_work_guard(context)), serverStrand(context), connectionFactory(std::move(factory))
{
	if (!connectionFactory)
	{
		throw std::runtime_error("Factory is required.");
	}
	assert(threads_ > 0);
}

TCPServer::~TCPServer() {
	stop();
	for (auto& thread : threadPool) {
		if (thread.joinable()) {
			thread.join();
		}
	}
	running = false;
	running.notify_all();
}

void TCPServer::start()
{
	if (running)
	{
		return;
	}
	for (std::size_t i = 0; i < threads; i++) {
		threadPool.emplace_back([this]() {
			try
			{
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

void TCPServer::stop() {
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

bool TCPServer::join(ConnectionPtr connection) {
	if (onConnect(connection)) {
		std::lock_guard<std::recursive_mutex> lock(conGuard);
		connections.push_back(connection);
		return true;
	}
	else {
		return false;
	}
}

void TCPServer::leave(ConnectionPtr connection) {
	std::lock_guard<std::recursive_mutex> lock(conGuard);
	auto it = std::find(connections.begin(), connections.end(), connection);
	if (it != connections.end()) {
		connections.erase(it);
	}
}

void TCPServer::addErrorHandler(std::function<bool(std::error_code, std::string_view, ConnectionPtr, asio::ip::tcp::socket*)> errorCallback) {
	std::unique_lock lock(handlerGuard);
	callbacks.onError.push_back(errorCallback);
}

void TCPServer::addConnectHandler(std::function<bool(ConnectionPtr)> connectCallback) {
	std::unique_lock lock(handlerGuard);
	callbacks.onConnect.push_back(connectCallback);
}

void TCPServer::addDisconnectHandler(std::function<void(ConnectionPtr)> disconnectCallback) {
	std::unique_lock lock(handlerGuard);
	callbacks.onDisconnect.push_back(disconnectCallback);
}

bool TCPServer::onError(std::error_code ec, std::string_view message, ConnectionPtr connection, asio::ip::tcp::socket* socket) {
	std::shared_lock lock(handlerGuard);
	bool ret = true;
	for (const auto& callback : callbacks.onError) {
		if (!callback(ec, message, connection, socket)) {
			ret = false;
		}
	}
	return ret;
}
bool TCPServer::onConnect(ConnectionPtr connection) {
	std::shared_lock lock(handlerGuard);
	for (const auto& callback : callbacks.onConnect) {
		if (!callback(connection)) {
			return false;
		}
	}
	return true;
}
void TCPServer::onDisconnect(ConnectionPtr connection) {
	leave(connection);
	std::shared_lock lock(handlerGuard);
	for (const auto& callback : callbacks.onDisconnect) {
		callback(connection);
	}
}

void TCPServer::do_accept() {
	serverStrand.post([this] {
		acceptor.async_accept(
			[this](std::error_code ec, asio::ip::tcp::socket socket) {
				if (!ec) {
					socket.lowest_layer().set_option(asio::ip::tcp::no_delay(true));
					asio::ip::address ip = socket.remote_endpoint().address();
					asio::ip::address realIP;
					if (!proxied) {
						realIP = ip;
					}
					else {
						proxyHeader proxyheader;
						proxyHeader::read_proxy_header(&socket, proxyheader);
						auto status = proxyheader.decode_header();
						if (status == proxyHeaderParseStatus::SuccessProxy) {
							realIP = asio::ip::make_address_v4(proxyheader.src_addr);
						}
						else {
							onError(std::make_error_code(std::errc::invalid_argument), "Proxy header failed " + std::to_string(static_cast<int>(status)), nullptr, &socket);
							return;
						}
					}
					ConnectionPtr conn = connectionFactory->create(std::move(socket), context, ip, realIP);
					conn->onErrorCb = [this, conn](std::error_code ec, std::string_view message) {this->onError(ec, message, conn); };
					conn->onDisconnectCb = [this, conn]() {this->onDisconnect(conn); };
					bool allowed = join(conn);
					if (allowed) {
						conn->start();
					}
					else {
						onError(std::make_error_code(std::errc::permission_denied), "Connection not allowed", conn, nullptr);
						conn->shutdown();
					}
				}
				else {
					onError(ec, "Accept failed", nullptr, &socket);
				}
				do_accept();
			});
		});
}




UDPServer::UDPServer(const asio::ip::address& ip_, unsigned short port_, std::size_t threads_)
	: workGuard(asio::make_work_guard(context)), ip(ip_), port(port_), socket(context, asio::ip::udp::endpoint(ip_, port_)), threads(threads_), recvBuffer(65535) {
	for (size_t i = 0; i < threads; i++)
	{
		threadPool.emplace_back([this]() {
			try {
				context.run();
			}
			catch (const std::exception& ec)
			{
				std::cout << ec.what(); //TBD
			}
			});
	}
	start_receive();
}
UDPServer::~UDPServer() {
	context.stop();
	for (auto& t : threadPool) {
		if (t.joinable()) {
			t.join();
		}
	}
}
void UDPServer::send(const asio::ip::udp::endpoint& to, std::vector<uint8_t>& data) {
	auto buffer = asio::buffer(data);
	socket.async_send_to(buffer, to, [data = std::move(data)](auto, auto) {});
}
void UDPServer::addHandler(std::function<void(UDPServer&, const asio::ip::udp::endpoint&, const std::vector<std::uint8_t>&)> handler)
{
	std::unique_lock lock(handlerGuard);
	dataHandlers.push_back(handler);
}
void UDPServer::start_receive() {
	socket.async_receive_from(
		asio::buffer(recvBuffer), remoteEndpoint,
		[this](std::error_code ec, std::size_t bytes_recvd) {
			if (!ec && bytes_recvd > 0) {
				std::vector<std::uint8_t> data(recvBuffer.begin(), recvBuffer.begin() + bytes_recvd);
				asio::ip::udp::endpoint endpoint = remoteEndpoint;
				std::shared_lock lock(handlerGuard);
				for (auto& handler : dataHandlers)
				{
					context.post([this, handler, endpoint, data] {
						handler(*this, endpoint, data);
						});

				}
			}
			start_receive();
		});
}