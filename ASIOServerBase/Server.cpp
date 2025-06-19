#include "Server.hpp"
#include <ranges>
#include <algorithm>
#include <iostream>
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