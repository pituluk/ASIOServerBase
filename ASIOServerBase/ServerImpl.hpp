#pragma once
#include "Server.hpp"
struct iConnectionData
{
    std::uint32_t connectedOn;
    std::string name;
    std::vector<std::uint8_t> buffer;
    size_t read_offset = 0;
};
template<typename ConnUserData>
struct iServerData {
    char empty = 0;
};

template <typename ConnUserData, typename ServerUserData>
struct iServerContext {
    asio::io_context& io;
    std::mutex& conMutex;
    std::vector<std::shared_ptr<ConnUserData, ServerUserData>>& conns;
    ServerUserData& userData;
};

using Server = TCPServer<iConnectionData, iServerData<iConnectionData>>;
using Connection = TCPConnection<iConnectionData, iServerData<iConnectionData>>;
using ServerData = iServerData<iConnectionData>;
using ConnectionData = iConnectionData;
using ServerContext = iServerContext<ConnectionData, ServerData>;