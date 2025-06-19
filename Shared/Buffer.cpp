#include "Buffer.hpp"
#include <iomanip> // byteStr()

/************************* WRITING *************************/

Buffer::Buffer() noexcept {
	buffer.reserve(200); //arbitrary value, gotta find average sw packet size
}
Buffer::Buffer(std::size_t size) noexcept {
	buffer.reserve(size);
}
Buffer::Buffer(std::vector<std::uint8_t>&& _buffer) noexcept :
	buffer(std::move(_buffer)) {
}
Buffer::Buffer(const std::vector<std::uint8_t>& _buffer) noexcept : buffer(_buffer) {};
Buffer::Buffer(std::span<const std::uint8_t> b) noexcept : buffer(b.begin(), b.end()) {};
void Buffer::setBuffer(std::vector<std::uint8_t>& _buffer) noexcept {
	buffer = _buffer;
}
const std::vector<uint8_t>& Buffer::getBuffer() const noexcept {
	return buffer;
}
std::vector<uint8_t>& Buffer::getBuffer() noexcept {
	return buffer;
}
void Buffer::clear() noexcept {
	buffer.clear();
	readOffset = 0;
}

std::string Buffer::byteStr(bool LE) const noexcept { //didnt add compile time check for LE/BE because I never used this function
	std::stringstream byteStr;
	byteStr << std::hex << std::setfill('0');

	if (LE == true) {
		for (std::size_t i = 0; i < buffer.size(); ++i)
			byteStr << std::setw(2) << (unsigned short)buffer[i] << " ";
	}
	else {
		std::size_t size = buffer.size();
		for (std::size_t i = 0; i < size; ++i)
			byteStr << std::setw(2) << (unsigned short)buffer[size - i - 1] << " ";
	}

	return byteStr.str();
}

template <class T> inline void Buffer::writeBytes(T val, bool LE) {
	std::size_t size = sizeof(T);
	if constexpr (isLE == true) {
		if (LE == true) {
			buffer.insert(buffer.end(), reinterpret_cast<const unsigned char*>(&val), reinterpret_cast<const unsigned char*>(&val + 1));
		}
		else {
			val = SwapEndian(val);
			buffer.insert(buffer.end(), reinterpret_cast<const unsigned char*>(&val), reinterpret_cast<const unsigned char*>(&val + 1));
		}
	}
	else //big endian machine
	{
		if (LE == true) {
			val = SwapEndian(val);
			buffer.insert(buffer.end(), reinterpret_cast<const unsigned char*>(&val), reinterpret_cast<const unsigned char*>(&val + 1));
		}
		else {
			buffer.insert(buffer.end(), reinterpret_cast<const unsigned char*>(&val), reinterpret_cast<const unsigned char*>(&val + 1));
		}
	}
}
void Buffer::writeEmpty(std::size_t len) noexcept {
	for (std::size_t i = 0; i < len; i++)
	{
		writeUInt8(0);
	}
}
void Buffer::writeVector(const std::vector<std::uint8_t>& data)
{
	buffer.insert(std::end(buffer), std::begin(data), std::end(data));
	//for (const unsigned char s : data) writeUInt8(s);
}
void Buffer::writeBool(bool val) noexcept {
	writeBytes<bool>(val);
}
void Buffer::writeStr(const std::string& str) noexcept {
	for (const unsigned char& s : str) writeUInt8(s);
}
void Buffer::writeWStr(const std::wstring& str) noexcept {
	for (const wchar_t& s : str) writeUInt16_LE(s);
}
void Buffer::writeStrU16LE(const std::string& str) noexcept
{
	writeUInt16_LE(str.size());
	for (const unsigned char& s : str) writeUInt8(s);
}
void Buffer::writeWStrU16LE(const std::wstring& str) noexcept
{
	writeUInt16_LE(str.size());
	for (const unsigned char& s : str) writeUInt16_LE(s);
}
void Buffer::writeStrU32LE(const std::string& str) noexcept
{
	writeUInt32_LE(str.size());
	for (const unsigned char& s : str) writeUInt8(s);
}
void Buffer::writeWStrU32LE(const std::wstring& str) noexcept
{
	writeUInt32_LE(str.size());
	for (const unsigned char& s : str) writeUInt16_LE(s);
}
void Buffer::writeStrU16BE(const std::string& str) noexcept
{
	writeUInt16_BE(str.size());
	for (const unsigned char& s : str) writeUInt8(s);
}
void Buffer::writeWStrU16BE(const std::wstring& str) noexcept
{
	writeUInt16_BE(str.size());
	for (const unsigned char& s : str) writeUInt16_BE(s);
}
void Buffer::writeStrU32BE(const std::string& str) noexcept
{
	writeUInt32_BE(str.size());
	for (const unsigned char& s : str) writeUInt8(s);
}
void Buffer::writeWStrU32BE(const std::wstring& str) noexcept
{
	writeUInt32_BE(str.size());
	for (const unsigned char& s : str) writeUInt16_BE(s);
}
void Buffer::writeInt8(std::int8_t val) noexcept {
	writeBytes<std::int8_t>(val);
}
void Buffer::writeUInt8(std::uint8_t val) noexcept {
	writeBytes<std::uint8_t>(val);
}

void Buffer::writeInt16_LE(std::int16_t val) noexcept {
	writeBytes<std::int16_t>(val);
}
void Buffer::writeInt16_BE(std::int16_t val) noexcept {
	writeBytes<std::int16_t>(val, false);
}
void Buffer::writeUInt16_LE(std::uint16_t val) noexcept {
	writeBytes<std::uint16_t>(val);
}
void Buffer::writeUInt16_BE(std::uint16_t val) noexcept {
	writeBytes<std::uint16_t>(val, false);
}

void Buffer::writeInt32_LE(std::int32_t val) noexcept {
	writeBytes<std::int32_t>(val);
}
void Buffer::writeInt32_BE(std::int32_t val) noexcept {
	writeBytes<std::int32_t>(val, false);
}
void Buffer::writeUInt32_LE(std::uint32_t val) noexcept {
	writeBytes<std::uint32_t>(val);
}
void Buffer::writeUInt32_BE(std::uint32_t val) noexcept {
	writeBytes<std::uint32_t>(val, false);
}

void Buffer::writeInt64_LE(std::int64_t val) noexcept {
	writeBytes<std::int64_t>(val);
}
void Buffer::writeInt64_BE(std::int64_t val) noexcept {
	writeBytes<std::int64_t>(val, false);
}
void Buffer::writeUInt64_LE(std::uint64_t val) noexcept {
	writeBytes<std::uint64_t>(val);
}
void Buffer::writeUInt64_BE(std::uint64_t val) noexcept {
	writeBytes<std::uint64_t>(val, false);
}

void Buffer::writeFloat_LE(float val) noexcept {
	writeBytes<float>(val);
}
void Buffer::writeFloat_BE(float val) noexcept {
	writeBytes<float>(val, false);
}
void Buffer::writeDouble_LE(double val) noexcept {
	writeBytes<double>(val);
}
void Buffer::writeDouble_BE(double val) noexcept {
	writeBytes<double>(val, false);
}

/************************* READING *************************/

void Buffer::setReadOffset(std::size_t newOffset) {
	if (readOffset >= buffer.size())
	{
		throw std::out_of_range("Buffer::setReadOffset out of range");
	}
	readOffset = newOffset;
}
std::size_t Buffer::getReadOffset() const noexcept {
	return readOffset;
}
template <class T> inline T Buffer::readBytes(bool LE) {
	T result = 0;
	std::size_t size = sizeof(T);

	// Do not overflow
	if (readOffset + size > buffer.size())
		throw std::out_of_range("Buffer::readBytes out of range");

	char* dst = (char*)&result;
	char* src = (char*)&buffer[readOffset];
	if constexpr (isLE == true)
	{
		if (LE == true) {
			for (std::size_t i = 0; i < size; ++i)
				dst[i] = src[i];
		}
		else {
			for (std::size_t i = 0; i < size; ++i)
				dst[i] = src[size - i - 1];
		}
	}
	else
	{
		if (LE == true) {
			for (std::size_t i = 0; i < size; ++i)
				dst[i] = src[size - i - 1];
		}
		else {
			for (std::size_t i = 0; i < size; ++i)
				dst[i] = src[i];
		}
	}
	readOffset += size;
	return result;
}

bool Buffer::readBool() {
	return readBytes<bool>();
}
std::vector<std::uint8_t> Buffer::readVec(std::size_t len) {
	if (readOffset + len > buffer.size())
		throw std::out_of_range("Buffer::readVec out of range");
	std::vector<std::uint8_t> result(buffer.begin() + readOffset, buffer.begin() + readOffset + len);
	readOffset += len;
	return result;
}
std::string Buffer::readStr(std::size_t len) {
	if (readOffset + len > buffer.size())
		throw std::out_of_range("Buffer::readStr out of range");
	std::string result(buffer.begin() + readOffset, buffer.begin() + readOffset + len);
	readOffset += len;
	return result;
}
std::string Buffer::readStrU16LE() {
	if (readOffset + sizeof(std::uint16_t) > buffer.size())
		throw std::out_of_range("Buffer::readStrU16LE out of range (length)");
	std::size_t length = readUInt16_LE();
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readStrU16LE out of range (data)");
	std::string result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::string Buffer::readStrU16BE() {
	if (readOffset + sizeof(std::uint16_t) > buffer.size())
		throw std::out_of_range("Buffer::readStrU16BE out of range (length)");
	std::size_t length = readUInt16_BE();
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readStrU16BE out of range (data)");
	std::string result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::string Buffer::readStrU32LE() {
	if (readOffset + sizeof(std::uint32_t) > buffer.size())
		throw std::out_of_range("Buffer::readStrU32LE out of range (length)");
	std::size_t length = readUInt32_LE();
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readStrU32LE out of range (data)");
	std::string result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::string Buffer::readStrU32BE() {
	if (readOffset + sizeof(std::uint32_t) > buffer.size())
		throw std::out_of_range("Buffer::readStrU32BE out of range (length)");
	std::size_t length = readUInt32_BE();
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readStrU32BE out of range (data)");
	std::string result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::string Buffer::readStrU16LE(std::size_t minlen) {
	if (readOffset + sizeof(std::uint16_t) > buffer.size())
		throw std::out_of_range("Buffer::readStrU16LE(minlen) out of range (length)");
	std::size_t length = readUInt16_LE();
	if (length < minlen)
		throw std::out_of_range("Buffer::readStrU16LE(minlen) length < minlen");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readStrU16LE(minlen) out of range (data)");
	std::string result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::string Buffer::readStrU16BE(std::size_t minlen) {
	if (readOffset + sizeof(std::uint16_t) > buffer.size())
		throw std::out_of_range("Buffer::readStrU16BE(minlen) out of range (length)");
	std::size_t length = readUInt16_BE();
	if (length < minlen)
		throw std::out_of_range("Buffer::readStrU16BE(minlen) length < minlen");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readStrU16BE(minlen) out of range (data)");
	std::string result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::string Buffer::readStrU32LE(std::size_t minlen) {
	if (readOffset + sizeof(std::uint32_t) > buffer.size())
		throw std::out_of_range("Buffer::readStrU32LE(minlen) out of range (length)");
	std::size_t length = readUInt32_LE();
	if (length < minlen)
		throw std::out_of_range("Buffer::readStrU32LE(minlen) length < minlen");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readStrU32LE(minlen) out of range (data)");
	std::string result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::string Buffer::readStrU32BE(std::size_t minlen) {
	if (readOffset + sizeof(std::uint32_t) > buffer.size())
		throw std::out_of_range("Buffer::readStrU32BE(minlen) out of range (length)");
	std::size_t length = readUInt32_BE();
	if (length < minlen)
		throw std::out_of_range("Buffer::readStrU32BE(minlen) length < minlen");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readStrU32BE(minlen) out of range (data)");
	std::string result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::string Buffer::readStrU16LE(std::size_t minlen, std::size_t maxlen) {
	if (readOffset + sizeof(std::uint16_t) > buffer.size())
		throw std::out_of_range("Buffer::readStrU16LE(minlen,maxlen) out of range (length)");
	std::size_t length = readUInt16_LE();
	if (length < minlen || length > maxlen)
		throw std::out_of_range("Buffer::readStrU16LE(minlen,maxlen) length out of bounds");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readStrU16LE(minlen,maxlen) out of range (data)");
	std::string result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::string Buffer::readStrU16BE(std::size_t minlen, std::size_t maxlen) {
	if (readOffset + sizeof(std::uint16_t) > buffer.size())
		throw std::out_of_range("Buffer::readStrU16BE(minlen,maxlen) out of range (length)");
	std::size_t length = readUInt16_BE();
	if (length < minlen || length > maxlen)
		throw std::out_of_range("Buffer::readStrU16BE(minlen,maxlen) length out of bounds");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readStrU16BE(minlen,maxlen) out of range (data)");
	std::string result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::string Buffer::readStrU32LE(std::size_t minlen, std::size_t maxlen) {
	if (readOffset + sizeof(std::uint32_t) > buffer.size())
		throw std::out_of_range("Buffer::readStrU32LE(minlen,maxlen) out of range (length)");
	std::size_t length = readUInt32_LE();
	if (length < minlen || length > maxlen)
		throw std::out_of_range("Buffer::readStrU32LE(minlen,maxlen) length out of bounds");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readStrU32LE(minlen,maxlen) out of range (data)");
	std::string result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::string Buffer::readStrU32BE(std::size_t minlen, std::size_t maxlen) {
	if (readOffset + sizeof(std::uint32_t) > buffer.size())
		throw std::out_of_range("Buffer::readStrU32BE(minlen,maxlen) out of range (length)");
	std::size_t length = readUInt32_BE();
	if (length < minlen || length > maxlen)
		throw std::out_of_range("Buffer::readStrU32BE(minlen,maxlen) length out of bounds");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readStrU32BE(minlen,maxlen) out of range (data)");
	std::string result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::wstring Buffer::readWStr(std::size_t len) {
	if (readOffset + (len * sizeof(wchar_t)) > buffer.size())
		throw std::out_of_range("Buffer::readWStr out of range");
	std::wstring result(buffer.begin() + readOffset, buffer.begin() + readOffset + (len * sizeof(wchar_t)));
	readOffset += len * sizeof(wchar_t);
	return result;
}
std::u16string Buffer::readU16Str(std::size_t len) {
	if (readOffset + (len * sizeof(char16_t)) > buffer.size())
		throw std::out_of_range("Buffer::readU16Str out of range");
	std::u16string result;
	result.assign((char16_t*)&buffer[readOffset], len);
	readOffset += len * sizeof(char16_t);
	return result;
}
std::wstring Buffer::readWStrU16LE() {
	if (readOffset + sizeof(std::uint16_t) > buffer.size())
		throw std::out_of_range("Buffer::readWStrU16LE out of range (length)");
	std::size_t length = readUInt16_LE();
	length = length * sizeof(wchar_t);
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readWStrU16LE out of range (data)");
	std::wstring result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::wstring Buffer::readWStrU16BE() {
	if (readOffset + sizeof(std::uint16_t) > buffer.size())
		throw std::out_of_range("Buffer::readWStrU16BE out of range (length)");
	std::size_t length = readUInt16_BE();
	length = length * sizeof(wchar_t);
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readWStrU16BE out of range (data)");
	std::wstring result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::wstring Buffer::readWStrU32LE() {
	if (readOffset + sizeof(std::uint32_t) > buffer.size())
		throw std::out_of_range("Buffer::readWStrU32LE out of range (length)");
	std::size_t length = readUInt32_LE();
	length = length * sizeof(wchar_t);
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readWStrU32LE out of range (data)");
	std::wstring result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::wstring Buffer::readWStrU32BE() {
	if (readOffset + sizeof(std::uint32_t) > buffer.size())
		throw std::out_of_range("Buffer::readWStrU32BE out of range (length)");
	std::size_t length = readUInt32_BE();
	length = length * sizeof(wchar_t);
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readWStrU32BE out of range (data)");
	std::wstring result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::wstring Buffer::readWStrU16LE(std::size_t minlen) {
	if (readOffset + sizeof(std::uint16_t) > buffer.size())
		throw std::out_of_range("Buffer::readWStrU16LE(minlen) out of range (length)");
	std::size_t length = readUInt16_LE();
	length = length * sizeof(wchar_t);
	if (length < minlen)
		throw std::out_of_range("Buffer::readWStrU16LE(minlen) length < minlen");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readWStrU16LE(minlen) out of range (data)");
	std::wstring result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::wstring Buffer::readWStrU16BE(std::size_t minlen) {
	if (readOffset + sizeof(std::uint16_t) > buffer.size())
		throw std::out_of_range("Buffer::readWStrU16BE(minlen) out of range (length)");
	std::size_t length = readUInt16_BE();
	length = length * sizeof(wchar_t);
	if (length < minlen)
		throw std::out_of_range("Buffer::readWStrU16BE(minlen) length < minlen");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readWStrU16BE(minlen) out of range (data)");
	std::wstring result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::wstring Buffer::readWStrU16LE(std::size_t minlen, std::size_t maxlen) {
	if (readOffset + sizeof(std::uint16_t) > buffer.size())
		throw std::out_of_range("Buffer::readWStrU16LE(minlen,maxlen) out of range (length)");
	std::size_t length = readUInt16_LE();
	length = length * sizeof(wchar_t);
	if (length < minlen || length > maxlen)
		throw std::out_of_range("Buffer::readWStrU16LE(minlen,maxlen) length out of bounds");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readWStrU16LE(minlen,maxlen) out of range (data)");
	std::wstring result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::wstring Buffer::readWStrU16BE(std::size_t minlen, std::size_t maxlen) {
	if (readOffset + sizeof(std::uint16_t) > buffer.size())
		throw std::out_of_range("Buffer::readWStrU16BE(minlen,maxlen) out of range (length)");
	std::size_t length = readUInt16_BE();
	length = length * sizeof(wchar_t);
	if (length < minlen || length > maxlen)
		throw std::out_of_range("Buffer::readWStrU16BE(minlen,maxlen) length out of bounds");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readWStrU16BE(minlen,maxlen) out of range (data)");
	std::wstring result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::wstring Buffer::readWStrU32LE(std::size_t minlen, std::size_t maxlen) {
	if (readOffset + sizeof(std::uint32_t) > buffer.size())
		throw std::out_of_range("Buffer::readWStrU32LE(minlen,maxlen) out of range (length)");
	std::size_t length = readUInt32_LE();
	length = length * sizeof(wchar_t);
	if (length < minlen || length > maxlen)
		throw std::out_of_range("Buffer::readWStrU32LE(minlen,maxlen) length out of bounds");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readWStrU32LE(minlen,maxlen) out of range (data)");
	std::wstring result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::wstring Buffer::readWStrU32BE(std::size_t minlen, std::size_t maxlen) {
	if (readOffset + sizeof(std::uint32_t) > buffer.size())
		throw std::out_of_range("Buffer::readWStrU32BE(minlen,maxlen) out of range (length)");
	std::size_t length = readUInt32_BE();
	length = length * sizeof(wchar_t);
	if (length < minlen || length > maxlen)
		throw std::out_of_range("Buffer::readWStrU32BE(minlen,maxlen) length out of bounds");
	if (readOffset + length > buffer.size())
		throw std::out_of_range("Buffer::readWStrU32BE(minlen,maxlen) out of range (data)");
	std::wstring result(buffer.begin() + readOffset, buffer.begin() + readOffset + length);
	readOffset += length;
	return result;
}
std::int8_t Buffer::readInt8() {
	return readBytes<std::int8_t>();
}
std::uint8_t Buffer::readUInt8() {
	return readBytes<std::uint8_t>();
}

std::int16_t Buffer::readInt16_LE() {
	return readBytes<std::int16_t>();
}
std::int16_t Buffer::readInt16_BE() {
	return readBytes<std::int16_t>(false);
}
std::uint16_t Buffer::readUInt16_LE() {
	return readBytes<std::uint16_t>();
}
std::uint16_t Buffer::readUInt16_BE() {
	return readBytes<std::uint16_t>(false);
}

std::int32_t Buffer::readInt32_LE() {
	return readBytes<std::int32_t>();
}
std::int32_t Buffer::readInt32_BE() {
	return readBytes<std::int32_t>(false);
}
std::uint32_t Buffer::readUInt32_LE() {
	return readBytes<std::uint32_t>();
}
std::uint32_t Buffer::readUInt32_BE() {
	return readBytes<std::uint32_t>(false);
}

std::int64_t Buffer::readInt64_LE() {
	return readBytes<std::int64_t>();
}
std::int64_t Buffer::readInt64_BE() {
	return readBytes<std::int64_t>(false);
}
std::uint64_t Buffer::readUInt64_LE() {
	return readBytes<std::uint64_t>();
}
std::uint64_t Buffer::readUInt64_BE() {
	return readBytes<std::uint64_t>(false);
}

float Buffer::readFloat_LE() {
	return readBytes<float>();
}
float Buffer::readFloat_BE() {
	return readBytes<float>(false);
}
double Buffer::readDouble_LE() {
	return readBytes<double>();
}
double Buffer::readDouble_BE() {
	return readBytes<double>(false);
}

Buffer::~Buffer() {
	clear(); //not needed I think
}