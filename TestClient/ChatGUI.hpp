#pragma once
#include "ftxui/component/captured_mouse.hpp"  // for ftxui
#include "ftxui/component/component.hpp"       // for Input, Renderer, Vertical
#include "ftxui/component/component_base.hpp"  // for ComponentBase
#include "ftxui/component/component_options.hpp"  // for InputOption
#include "ftxui/component/screen_interactive.hpp"  // for Component, ScreenInteractive
#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
enum class AppState
{
	LOGIN,
	CHAT,
};
struct Channel
{
	std::string name;
};
struct User
{
	std::string username;
	std::uint8_t permissionsLevel;
};
struct ChatMessage
{
	ChatMessage(std::string_view u, std::string_view t) : username(u), text(t) {}
	std::string username;
	std::string text;
};

class ChatClient;
class ChatGUIManager //I DONT UNDERSTAND THIS LIBRARY, THIS TUI SUCKS
{
	struct LoginForm
	{
		std::mutex mtx;
		std::string username_input;
		std::string password_input;
		bool login_error = false; //mtx protected
		ftxui::Component input_login;
		ftxui::Component input_password;
		ftxui::Component input_button;
		std::string errorMessage; //mtx protected
	};
	struct ChatForm
	{
		ftxui::Component input_message;
		std::string message_input;
		ftxui::Component send_button;
		std::vector<ChatMessage> messages;
		std::mutex messagesMtx;
	};
public:
	ChatGUIManager(ChatClient* client);
	std::atomic<AppState> state;
	void setState(AppState state);
	void addChatMessage(std::string_view name, std::string_view message);
	void setChannels(std::vector<Channel> channels);
	void setLoginError(std::string s) { std::lock_guard lock(loginForm.mtx); loginForm.errorMessage = s; loginForm.login_error = true; }
private:
	std::thread chatThread;
	ftxui::Component chat_renderer;
	ftxui::Component login_renderer;
	ChatClient* client;
	std::vector<Channel> channels;
	std::vector<User> usersOnChannel;
	LoginForm loginForm;
	ftxui::Component createLoginForm();
	ChatForm chatForm;
	ftxui::Component createChatForm();
};