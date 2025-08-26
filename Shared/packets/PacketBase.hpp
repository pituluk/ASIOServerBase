#pragma once
#include "Buffer.hpp"
#include <iostream>
template <typename Derived>
class PacketBase
{
public:
	explicit PacketBase(std::vector<std::uint8_t> data) : b(std::move(data)) { b.setReadOffset(2); }
	PacketBase() = default;
	std::vector<std::uint8_t>& getBuffer() { return b.getBuffer(); }
	explicit operator bool() const { return readSuccess; }
	virtual ~PacketBase() = default;
	template<typename... Args>
	void write(Args&&... args) {
		writeHeader();
		static_cast<Derived*>(this)->_write(std::forward<Args>(args)...);
		fixSize();
	}
	virtual std::uint16_t getID() { return 0x0000; }
protected:
	void writeHeader()
	{
		b.writeUInt32_LE(0); // size must be fixed later
		std::uint16_t id = getID();
		b.writeUInt16_LE(id);
	}
	void fixSize()
	{
		auto& buf = b.getBuffer();
		std::uint32_t size = buf.size();
		buf[0] = static_cast<uint8_t>((size >> 24) & 0xFF);
		buf[1] = static_cast<uint8_t>((size >> 16) & 0xFF);
		buf[2] = static_cast<uint8_t>((size >> 8) & 0xFF);
		buf[3] = static_cast<uint8_t>((size) & 0xFF);
	}
	void read() { //called only from constructors
		try {
			_read();
		}
		catch (const std::exception& e) {
			std::cout << "PacketBase error: " << e.what() << '\n'; //replace with whatever
			readSuccess = false;
		}
	}
	virtual void _read() = 0;
	Buffer b;
	bool readSuccess = true;
};