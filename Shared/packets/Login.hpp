#pragma once
#include "PacketBase.hpp"
enum class LOGIN_RESULT : std::uint8_t {
    FAILURE = 0,
    SUCCESS = 1
};
class SLogin : public PacketBase<SLogin> //for server use
{
public:
    explicit SLogin(std::vector<std::uint8_t> data) : PacketBase<SLogin>(std::move(data)) {
        read();
    }
    std::uint16_t getID() override {
        return 0x0101;
    }
    SLogin() {}
    void _read() override {
        login = b.readStrU16LE();
    }
    void _write(LOGIN_RESULT result)
    {
        b.writeUInt8(static_cast<std::uint8_t>(result));
    }
    std::string login;
};
class Login : public PacketBase<Login> //for client use
{
public:
    explicit Login(std::vector<std::uint8_t> data) : PacketBase<Login>(std::move(data)) {
        read();
    }
    std::uint16_t getID() override {
        return 0x0101;
    }
    Login() {}
    void _read() override {
        result = static_cast<LOGIN_RESULT>(b.readUInt8());
    }
    void _write(std::string login)
    {
        b.writeStrU16LE(login);
    }
    LOGIN_RESULT result;
};