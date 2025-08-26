// TestClient.cpp : Ten plik zawiera funkcję „main”. W nim rozpoczyna się i kończy wykonywanie programu.
//

#include "ClientImpl.hpp"
#include "packets/Login.hpp"
#include "packets/Message.hpp"

#include "ChatGUI.hpp"
#include <deque>
#include <iostream>
#include <string>
int main()
{
	asio::io_context context;
	auto workGuard = asio::make_work_guard(context);
	std::thread contextThread([&context]() {
		context.run();
		});
	ChatClient client(context);
	client.connect("127.0.0.1", 7777);
	while (!client.connected())
	{
		std::this_thread::yield();
	}
	ChatGUIManager manager(&client);
	client.setPacketHandler([&manager](std::vector<std::uint8_t> data) {
		if (data[0] == 0x01)
		{
			if (data[1] == 0x01)
			{
				Login packet(std::move(data));
				if (packet.result == LOGIN_RESULT::SUCCESS)
				{
					manager.setState(AppState::CHAT);
				}
				else
				{
					manager.setLoginError("User already logged in.");
				}
			}
			else if (data[1] == 0x02)
			{
				Message packet(std::move(data));
				manager.addChatMessage(packet.name, packet.message);
			}
		}
		});

	while (client.connected())
	{
		std::this_thread::yield();
	}
	contextThread.join();
}

// Uruchomienie programu: Ctrl + F5 lub menu Debugowanie > Uruchom bez debugowania
// Debugowanie programu: F5 lub menu Debugowanie > Rozpocznij debugowanie

// Porady dotyczące rozpoczynania pracy:
//   1. Użyj okna Eksploratora rozwiązań, aby dodać pliki i zarządzać nimi
//   2. Użyj okna programu Team Explorer, aby nawiązać połączenie z kontrolą źródła
//   3. Użyj okna Dane wyjściowe, aby sprawdzić dane wyjściowe kompilacji i inne komunikaty
//   4. Użyj okna Lista błędów, aby zobaczyć błędy
//   5. Wybierz pozycję Projekt > Dodaj nowy element, aby utworzyć nowe pliki kodu, lub wybierz pozycję Projekt > Dodaj istniejący element, aby dodać istniejące pliku kodu do projektu
//   6. Aby w przyszłości ponownie otworzyć ten projekt, przejdź do pozycji Plik > Otwórz > Projekt i wybierz plik sln
