#pragma once
#include "PacketBase.hpp"
class SMessage : public PacketBase<SMessage> //for server use
{
public:
    explicit SMessage(std::vector<std::uint8_t> data) : PacketBase<SMessage>(std::move(data)) {
        read();
    }
    std::uint16_t getID() override {
        return 0x0201;
    }
    SMessage() {}
    void _read() override {
        message = b.readStrU16LE();
    }
    void _write(std::uint64_t id,std::string name,std::string message)
    {
        b.writeUInt64_LE(id);
        b.writeStrU16LE(name);
        b.writeStrU16LE(message);
    }
    std::string message;
};
class Message : public PacketBase<Message> //for client use
{
public:
    explicit Message(std::vector<std::uint8_t> data) : PacketBase<Message>(std::move(data)) {
        read();
    }
    std::uint16_t getID() override {
        return 0x0201;
    }
    Message() {}
    void _read() override {
        id = b.readUInt64_LE();
        name = b.readStrU16LE();
        message = b.readStrU16LE();
    }
    void _write(std::string message)
    {
        b.writeStrU16LE(message);
    }
    std::uint64_t id;
    std::string name;
    std::string message;
};