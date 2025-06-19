#pragma once

//original by m-byte918 https://github.com/m-byte918/Binary-Reader-Writer
//edited by pituluk https://github.com/pituluk
#include <vector>  // buffers
#include <sstream> // strings, byteStr()
#include <span>
#include <bit>
#include <array>
#include <algorithm>
template<typename T>
T SwapEndian(T& val) {
	auto src = std::bit_cast<std::array<std::byte, sizeof(T)>>(val);
	std::array<std::byte, sizeof(T)> dst;
	std::reverse_copy(src.begin(), src.end(), dst.begin());
	return std::bit_cast<T>(dst);
}
template<typename T>
consteval T SwapEndian(T&& val) {
	auto src = std::bit_cast<std::array<std::byte, sizeof(T)>>(val);
	std::array<std::byte, sizeof(T)> dst;
	std::reverse_copy(src.begin(), src.end(), dst.begin());
	return std::bit_cast<T>(dst);
}
consteval bool getEndiannes()
{
	if constexpr (std::endian::native == std::endian::little)
	{
		return true;
	}
	else if constexpr (std::endian::native == std::endian::big)
	{
		return false;
	}
	else
	{
		throw "Mixed endian";
	}
}
class Buffer {
public:
	Buffer() noexcept;
	Buffer(std::size_t size) noexcept;
	Buffer(std::vector<std::uint8_t>&&) noexcept;
	Buffer(const std::vector<std::uint8_t>&) noexcept;
	Buffer(std::span<const std::uint8_t>) noexcept;
	void setBuffer(std::vector<std::uint8_t>&) noexcept;
	const std::vector<std::uint8_t>& getBuffer() const noexcept;
	std::vector<std::uint8_t>& getBuffer() noexcept;
	void clear() noexcept;

	std::string byteStr(bool LE = true) const noexcept;

	/************************** Writing ***************************/

	template <class T> inline void writeBytes(T val, bool LE = true);
	void writeEmpty(std::size_t len) noexcept;
	void writeVector(const std::vector<uint8_t>& data);
	void writeBool(bool) noexcept;
	void writeWStr(const std::wstring&) noexcept;
	void writeStr(const std::string&) noexcept;
	void writeStrU16LE(const std::string& str) noexcept;
	void writeWStrU16LE(const std::wstring& str) noexcept;
	void writeStrU32LE(const std::string& str) noexcept;
	void writeWStrU32LE(const std::wstring& str) noexcept;
	void writeStrU16BE(const std::string& str) noexcept;
	void writeWStrU16BE(const std::wstring& str) noexcept;
	void writeStrU32BE(const std::string& str) noexcept;
	void writeWStrU32BE(const std::wstring& str) noexcept;

	void writeInt8(std::int8_t) noexcept;
	void writeUInt8(std::uint8_t) noexcept;

	void writeInt16_LE(std::int16_t) noexcept;
	void writeInt16_BE(std::int16_t) noexcept;
	void writeUInt16_LE(std::uint16_t) noexcept;
	void writeUInt16_BE(std::uint16_t) noexcept;

	void writeInt32_LE(std::int32_t) noexcept;
	void writeInt32_BE(std::int32_t) noexcept;
	void writeUInt32_LE(std::uint32_t) noexcept;
	void writeUInt32_BE(std::uint32_t) noexcept;

	void writeInt64_LE(std::int64_t) noexcept;
	void writeInt64_BE(std::int64_t) noexcept;
	void writeUInt64_LE(std::uint64_t) noexcept;
	void writeUInt64_BE(std::uint64_t) noexcept;

	void writeFloat_LE(float) noexcept;
	void writeFloat_BE(float) noexcept;
	void writeDouble_LE(double) noexcept;
	void writeDouble_BE(double) noexcept;

	/************************** Reading ***************************/

	void setReadOffset(size_t);
	size_t getReadOffset() const noexcept;
	template <class T> inline T readBytes(bool LE = true);

	bool readBool();
	std::vector<uint8_t> readVec(size_t len);
	std::string readStr(size_t len);
	std::string readStrU16LE();
	std::string readStrU16BE();
	std::string readStrU32LE();
	std::string readStrU32BE();
	std::string readStrU16LE(size_t minlen);
	std::string readStrU16BE(size_t minlen);
	std::string readStrU16LE(size_t minlen, size_t maxlen);
	std::string readStrU16BE(size_t minlen, size_t maxlen);
	std::string readStrU32LE(size_t minlen);
	std::string readStrU32BE(size_t minlen);
	std::string readStrU32LE(size_t minlen, size_t maxlen);
	std::string readStrU32BE(size_t minlen, size_t maxlen);
	std::wstring readWStr(size_t len);
	std::wstring readWStrU16LE();
	std::wstring readWStrU16BE();
	std::wstring readWStrU32LE();
	std::wstring readWStrU32BE();
	std::wstring readWStrU16LE(size_t minlen);
	std::wstring readWStrU16BE(size_t minlen);
	std::wstring readWStrU16LE(size_t minlen, size_t maxlen);
	std::wstring readWStrU16BE(size_t minlen, size_t maxlen);
	std::wstring readWStrU32LE(size_t minlen, size_t maxlen);
	std::wstring readWStrU32BE(size_t minlen, size_t maxlen);
	std::u16string readU16Str(size_t len);
	std::int8_t readInt8();
	std::uint8_t readUInt8();

	std::int16_t readInt16_LE();
	std::int16_t readInt16_BE();
	std::uint16_t readUInt16_LE();
	std::uint16_t readUInt16_BE();

	std::int32_t readInt32_LE();
	std::int32_t readInt32_BE();
	std::uint32_t readUInt32_LE();
	std::uint32_t readUInt32_BE();

	std::int64_t readInt64_LE();
	std::int64_t readInt64_BE();
	std::uint64_t readUInt64_LE();
	std::uint64_t readUInt64_BE();

	float readFloat_LE();
	float readFloat_BE();
	double readDouble_LE();
	double readDouble_BE();

	~Buffer();
private:
	std::vector<std::uint8_t> buffer;
	size_t readOffset = 0;
	static constexpr bool isLE = getEndiannes();
}
;