#include "ChatGUI.hpp"
#include "ClientImpl.hpp"
#include <packets/Login.hpp>
#include <packets/Message.hpp>
ChatGUIManager::ChatGUIManager(ChatClient* client) : client(client)
{
	state = AppState::LOGIN;
	using namespace ftxui;
	login_renderer = this->createLoginForm();
	chat_renderer = this->createChatForm();
	chatThread = std::thread([this]() {
		static auto container = Container::Tab({
	login_renderer,
	chat_renderer ? chat_renderer : Renderer([] { return text("Loading..."); })
			}, (int*)&state); // Make sure AppState::LOGIN == 0, CHAT == 1
		static auto main_app = Renderer(container, [&] {
			return container->Render();
			});
		static auto screen = ScreenInteractive::TerminalOutput();
		screen.Loop(main_app);
		});


}

ftxui::Component ChatGUIManager::createLoginForm()
{
	using namespace ftxui;
	InputOption password_option;
	password_option.password = true;
	loginForm.input_login = Input(&loginForm.username_input, "Username");
	loginForm.input_login |= CatchEvent([&](Event event) {
		// If it's a character and invalid, block it
		if (event.input() == "\n")
		{
			return true;
		}
		if (event.is_character()) {
			char c = event.character()[0];
			// Example: block newlines or control characters
			if (c == '\n' || c == '\r' || !isprint(c)) {
				return true;  // Block the event
			}
		}
		return false;  // Let the event through (Tab, Enter, etc.)
		});
	loginForm.input_password = Input(&loginForm.password_input, "Password", password_option);
	loginForm.input_password |= CatchEvent([&](Event event) {
		// If it's a character and invalid, block it
		if (event.input() == "\n")
		{
			return true;
		}
		if (event.is_character()) {
			char c = event.character()[0];
			// Example: block newlines or control characters
			if (c == '\n' || c == '\r' || !isprint(c)) {
				return true;  // Block the event
			}
		}
		return false;  // Let the event through (Tab, Enter, etc.)
		});
	loginForm.input_button = Button("Login", [&] {
		if (!loginForm.username_input.empty() && !loginForm.password_input.empty()) {
			loginForm.login_error = false;
			Login packet;
			packet.write(loginForm.username_input, loginForm.password_input);
			client->send(std::move(packet.getBuffer()));
		}
		else {
			loginForm.login_error = true;
		}
		});
	Component login_form = Container::Vertical({
		loginForm.input_login,
		loginForm.input_password,
		loginForm.input_button
		});

	auto login_renderer = Renderer(login_form, [&] {
		std::vector<Element> children = {
			text("Login") | bold | center,
			separator(),
			loginForm.input_login->Render(),
			loginForm.input_password->Render(),
			loginForm.input_button->Render()
		};
		if (loginForm.login_error) {
			{
				std::lock_guard lock(loginForm.mtx);
				if (!loginForm.errorMessage.empty())
				{
					children.push_back(text(loginForm.errorMessage) | color(Color::Red));
				}
			}
			if (loginForm.username_input.empty() || loginForm.password_input.empty()) {
				children.push_back(text("Error: Both fields required") | color(Color::Red));
			}
		}
		return vbox(children) | border | size(WIDTH, EQUAL, 50) | center;
		});

	return login_renderer;
}
ftxui::Component ChatGUIManager::createChatForm() {
	using namespace ftxui;

	// Message input field
	chatForm.input_message = Input(&chatForm.message_input, "Type a message");
	chatForm.input_message |= CatchEvent([&](Event event) {
		// If it's a character and invalid, block it
		if (event.input() == "\n")
		{
			if (!chatForm.message_input.empty()) {
				// Handle sending message logic here, e.g.:
				Message packet;
				packet.write(chatForm.message_input);
				client->send(std::move(packet.getBuffer()));
				chatForm.message_input.clear();
			}
			return true;
		}
		if (event.is_character()) {
			char c = event.character()[0];
			// Example: block newlines or control characters
			if (!isprint(c)) {
				return true;  // Block the event
			}
		}
		return false;  // Let the event through (Tab, Enter, etc.)
		});
	// Send button
	chatForm.send_button = Button("Send", [&] {
		if (!chatForm.message_input.empty()) {
			// Handle sending message logic here, e.g.:
			Message packet;
			packet.write(chatForm.message_input);
			client->send(std::move(packet.getBuffer()));
			chatForm.message_input.clear();
		}
		});

	// Container for input and button horizontally
	auto input_container = Container::Horizontal({
		chatForm.input_message,
		chatForm.send_button
		});

	// Container for the whole chat form vertically
	auto chat_form_container = Container::Vertical({
		// We will create a renderer for messages separately, so this container is empty here
		// but you can add a scrollable list component for messages later
		input_container
		});

	// Renderer for chat form UI
	auto chat_renderer = Renderer(chat_form_container, [this] {
		// Render message list
		std::vector<Element> messages_elements;
		{
			std::lock_guard lock(chatForm.messagesMtx);
			for (const auto& msg : chatForm.messages) {
				// Display username and message text side by side
				messages_elements.push_back(
					hbox({
						text(msg.username) | color(Color::Blue) | bold,
						text(": "),
						text(msg.text)
						})
				);
			}
		}
		auto messages_box = vbox(messages_elements) | frame | size(HEIGHT, GREATER_THAN, 20);

		// Render input + button horizontally
		auto input_row = hbox({
			chatForm.input_message->Render() | yflex_grow,
			chatForm.send_button->Render() | size(WIDTH, EQUAL, 10)
			});

		// Compose full layout with separator line
		return vbox({
			messages_box,
			separator(),
			input_row
			}) | border | flex;
		});

	return chat_renderer;
}
void ChatGUIManager::setState(AppState state_)
{
	state = state_;
}
void ChatGUIManager::addChatMessage(std::string_view name, std::string_view message)
{
	std::lock_guard lock(chatForm.messagesMtx);
	chatForm.messages.emplace_back(name, message);
}
void ChatGUIManager::setChannels(std::vector<Channel> channels)
{

}