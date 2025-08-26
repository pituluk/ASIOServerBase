#pragma once
#include "Client.hpp"
TCPClient::TCPClient(asio::io_context& io_context) : strand(io_context), resolver_(io_context), socket_(PlainSocket(io_context)), use_ssl_(false)
{
}
TCPClient::TCPClient(asio::io_context& io_context, asio::ssl::context& ssl_context) try : strand(io_context), resolver_(io_context), use_ssl_(true), socket_(SslSocket(strand.context(), ssl_context))
{
}
catch (const asio::error_code& er)
{
	onError(er, er.message());
}
void TCPClient::connect(const std::string& host, std::uint16_t port) {
	host_ = host;
	port_ = port;
	this->disconnect();
	markedToDisconnect = false;
	auto endpoints = resolver_.resolve(host_, std::to_string(port_));
	std::visit([&](auto& sock) {
		auto& raw = sock.lowest_layer();
		asio::async_connect(raw, endpoints,
			asio::bind_executor(strand,
				[this](std::error_code ec, asio::ip::tcp::endpoint) {
					if (!ec) {
						std::visit([](auto& sock) {
							sock.lowest_layer().set_option(asio::ip::tcp::no_delay(true));
							}, socket_);
						if (use_ssl_) {
							auto& ssl_sock = std::get<SslSocket>(socket_);
							ssl_sock.async_handshake(asio::ssl::stream_base::client,
								asio::bind_executor(strand,
									[this](std::error_code ec) {
										if (!ec) {
											connected_ = true;
											onConnected();
											do_read();
										}
										else {
											onError(ec, "SSL Handshake failed");
											disconnect();
										}
									}));
						}
						else {
							connected_ = true;
							onConnected();
							do_read();
						}
					}
					else {
						onError(ec, "Connect");
					}
				}));
		}, socket_);
}
void TCPClient::disconnect()
{
	if (!connected_)
	{
		return;
	}
	markedToDisconnect = true;
	asio::dispatch(this->strand, [this]() {
		if (!this->write_queue_.empty())
		{
			return;
		}
		connected_ = false;
		std::visit([this](auto& sock)
			{
				std::error_code ec;
				if constexpr (std::is_same_v<std::decay_t<decltype(sock)>, SslSocket>) {
					sock.shutdown(ec);  // SSL shutdown
					if (ec && ec != asio::error::eof && ec != asio::ssl::error::stream_truncated) {
						onError(ec, "SSL shutdown");
						ec.clear();
					}
				}
				sock.lowest_layer().cancel(ec); // Cancel ops
				if (ec)
				{
					onError(ec, "TCPClient::disconnect cancel");
					ec.clear();
				}

				sock.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
				if (ec && ec != asio::error::not_connected)
				{
					onError(ec, "TCPClient::disconnect shutdown");
					ec.clear();
				}
				sock.lowest_layer().close(ec);
				if (ec && ec != asio::error::not_connected)
				{
					onError(ec, "TCPClient::disconnect close");
					ec.clear();
				}
				this->onDisconnect();
			}, socket_);
		});
}

void TCPClient::send(std::vector<std::uint8_t> data)
{
	asio::post(strand, [this, data = std::move(data)]() {
		bool write_in_progress = !write_queue_.empty();
		write_queue_.push_back(std::move(data));
		if (!write_in_progress) {
			do_write();
		}
		});
}

void TCPClient::do_read() {
	std::visit([this](auto& sock)
		{
			sock.async_read_some(asio::buffer(read_buffer_),
				asio::bind_executor(strand,
					[this](std::error_code ec, std::size_t length) {
						if (!ec) {
							if (length > 0) { //need research if this is needed, is it possible to have 0 len but no ec???
								std::vector<std::uint8_t> data(read_buffer_.begin(), read_buffer_.begin() + length);
								onData(data);
								do_read();
							}
							else {
								onError(ec, "do_read() failed");
								disconnect();
							}
						}
						else {
							if (ec != asio::error::eof && ec != asio::error::connection_reset) {
								onError(ec, "do_read() failed");
							}
							disconnect();
						}
					}));
		}, socket_);
}

void TCPClient::do_write() {
	std::visit([this](auto& sock)
		{
			asio::async_write(sock, asio::buffer(write_queue_.front()),
				asio::bind_executor(strand,
					[this](std::error_code ec, std::size_t /*length*/) {
						if (!ec) {
							write_queue_.pop_front();
							if (!write_queue_.empty()) {
								do_write();
							}
							else if (markedToDisconnect == true)
							{
								disconnect(); //it was waiting for us to finish sending all outgoing packets, now disconnect
							}
						}
						else {
							onError(ec, "do_write() failed");
							disconnect();
						}
					}));
		}, socket_);
}