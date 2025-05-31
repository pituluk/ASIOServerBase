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

// --- TCPConnection implementation ---
TCPConnection::TCPConnection(std::uint64_t id_, asio::ip::tcp::socket socket_, TCPServer* server_, asio::ip::address ip_, asio::ip::address realIP_, asio::io_context& io_context)
    : id(id_), socket(std::move(socket_)), server(server_), ip(ip_), realIP(realIP_), strand(io_context), read_buffer(65535) {
}

void TCPConnection::start() {
    do_read();
}

void TCPConnection::write(const std::vector<std::uint8_t>& data) {
    auto self = shared_from_this();
    asio::post(strand, [this, self, data]() {
        bool write_in_progress = !write_queue.empty();
        write_queue.push_back(data);
        if (!write_in_progress) {
            do_write();
        }
        });
}

void TCPConnection::disconnect() {
    if (disconnected)
    {
        return;
    }
    disconnected = true;
    auto self = shared_from_this();
    asio::dispatch(strand, [this, self]() {
        if (socket.is_open()) {
            socket.shutdown(asio::socket_base::shutdown_both);
            socket.close();
        }
        server->leave(shared_from_this());
        });
}

void TCPConnection::shutdown() {
    if (disconnected)
    {
        return;
    }
    disconnected = true;
    auto self = shared_from_this();
    asio::dispatch(strand, [this, self]() {
        if (socket.is_open()) {
            socket.shutdown(asio::socket_base::shutdown_both);
            socket.close();
        }
        });
}

void TCPConnection::do_read() {
    auto self = shared_from_this();
    
    auto buf = asio::buffer(this->read_buffer.data(), this->read_buffer.size());
    socket.async_read_some(
        buf,
        asio::bind_executor(strand, [this, self](const std::error_code& ec, std::size_t length) {
            if (!ec && length > 0) {
                std::vector<std::uint8_t> data(read_buffer.begin(), read_buffer.begin() + length);
                server->onData(self, std::move(data));
                do_read();
            }
            else if (ec != asio::error::operation_aborted) {
                disconnect();
            }
            })
    );
}

void TCPConnection::do_write() {
    auto self = shared_from_this();
    asio::async_write(
        socket,
        asio::buffer(write_queue.front()),
        asio::bind_executor(strand, [this, self](std::error_code ec, std::size_t /*length*/) {
            if (!ec) {
                write_queue.pop_front();
                if (!write_queue.empty()) {
                    do_write();
                }
            }
            else {
                server->onError(ec, "Write failed", self, std::nullopt);
                disconnect();
            }
            })
    );
}

// --- TCPServer implementation ---
TCPServer::TCPServer(asio::ip::tcp::endpoint endpt, bool useProxy, std::size_t threads_)
    : endpoint(endpt), acceptor(context, endpt), threads(threads_), proxied(useProxy) {
    for (std::size_t i = 0; i < threads; i++) {
        threadPool.emplace_back([this]() { this->context.run(); });
    }
    do_accept();
}

TCPServer::~TCPServer() {
    for (auto connection : connections) {
        connection->shutdown();
    }
    context.stop();
    for (auto& thread : threadPool) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

bool TCPServer::join(std::shared_ptr<TCPConnection> connection) {
    if (onConnect(connection)) {
        std::lock_guard<std::recursive_mutex> lock(conGuard);
        connections.push_back(connection);
        return true;
    }
    else {
        return false;
    }
}

void TCPServer::leave(std::shared_ptr<TCPConnection> connection) {
    onDisconnect(connection);
    std::lock_guard<std::recursive_mutex> lock(conGuard);
    auto it = std::find(connections.begin(), connections.end(), connection);
    if (it != connections.end()) {
        connections.erase(it);
    }
}

void TCPServer::addHandler(std::function<bool(std::error_code, std::string_view, std::optional<std::shared_ptr<TCPConnection>>, std::optional<asio::ip::tcp::socket*>)> errorCallback) {
    std::unique_lock lock(handlerGuard);
    errorCallbacks.push_back(errorCallback);
}
void TCPServer::addHandler(std::function<bool(std::shared_ptr<TCPConnection>)> connectCallback) {
    std::unique_lock lock(handlerGuard);
    connectCallbacks.push_back(connectCallback);
}
void TCPServer::addHandler(std::function<void(std::shared_ptr<TCPConnection>)> disconnectCallback) {
    std::unique_lock lock(handlerGuard);
    disconnectCallbacks.push_back(disconnectCallback);
}
void TCPServer::addHandler(std::function<void(std::shared_ptr<TCPConnection>, const std::vector<std::uint8_t>&)> dataCallback) {
    std::unique_lock lock(handlerGuard);
    dataCallbacks.push_back(dataCallback);
}

bool TCPServer::onError(std::error_code ec, std::string_view message, std::optional<std::shared_ptr<TCPConnection>> connection, std::optional<asio::ip::tcp::socket*> socket) {
    std::shared_lock lock(handlerGuard);
    bool ret = true;
    for (const auto& callback : errorCallbacks) {
        if (!callback(ec, message, connection, socket)) {
            ret = false;
        }
    }
    return ret;
}
bool TCPServer::onConnect(std::shared_ptr<TCPConnection> connection) {
    std::shared_lock lock(handlerGuard);
    for (const auto& callback : connectCallbacks) {
        if (!callback(connection)) {
            return false;
        }
    }
    return true;
}
void TCPServer::onDisconnect(std::shared_ptr<TCPConnection> connection) {
    std::shared_lock lock(handlerGuard);
    for (const auto& callback : disconnectCallbacks) {
        callback(connection);
    }
}
void TCPServer::onData(std::shared_ptr<TCPConnection> connection, const std::vector<std::uint8_t> data) {
    std::shared_lock lock(handlerGuard);
    for (const auto& callback : dataCallbacks) {
        callback(connection, data);
    }
}

void TCPServer::do_accept() {
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
                auto conn = std::make_shared<TCPConnection>(connectionID, std::move(socket), this, ip, realIP, context);
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
}


void TCPServer::read_proxy_header(asio::ip::tcp::socket* s, proxyHeader& header) {
    asio::read(*s, asio::buffer(header.data(), header.size()));
}