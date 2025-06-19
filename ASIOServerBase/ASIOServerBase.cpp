#include <iostream>
#include "ServerImpl.hpp"
#include <chrono>

void udpOnData(UDPServer& server, const asio::ip::udp::endpoint& remote, const std::vector<std::uint8_t>& data)
{
	std::string s(data.begin(), data.end());
	std::cout << "[UDP] Received data from:" << remote.address().to_string() << ":" << remote.port() << " TID:" << std::this_thread::get_id() << " Size:" << data.size() << "\nMessage: " << s << std::endl;
	std::vector<std::uint8_t> resend(s.begin(), s.end());
	server.send(remote, resend);
}
int main()
{
	Server server(asio::ip::make_address("0.0.0.0"), 7777, false, 8);
	bool running = true;
	std::cout << "[TCP] Running on " << server.ip << ":" << server.port << std::endl;

	UDPServer server2(asio::ip::make_address("0.0.0.0"), 7777, 8);
	server2.addHandler(udpOnData);
	std::cout << "[UDP] Running on " << server2.ip << ":" << server2.port << std::endl;
	while (running == true)
	{
		std::string input;
		std::cin >> input;
		if (input == "stop" || input == "s")
		{
			running = false;
		}
	}
}
