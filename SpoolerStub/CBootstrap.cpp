#include <memory>
#include "CBootstrap.hpp"
#include "CHooks.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/msvc_sink.h>
#include "CWebSocket.hpp"

class debug_sink final : public spdlog::sinks::base_sink<spdlog::details::null_mutex>
{
protected:
	void sink_it_(const spdlog::details::log_msg &msg) override
	{
		spdlog::memory_buf_t formatted;
		this->formatter_->format(msg, formatted);
		formatted.push_back('\0');
		std::wstring wideString(formatted.begin(), formatted.end());

		OutputDebugStringW(wideString.c_str());
	}

	void flush_() noexcept override
	{
	}
};

CBootstrap::CBootstrap()
{
	auto sink = std::make_shared<debug_sink>();
	static auto S_logger = std::make_shared<spdlog::logger>("SpoolStub", sink);

	spdlog::set_default_logger(S_logger);
	spdlog::set_level(spdlog::level::debug);
	m_Hooks = std::make_unique<CHooks>();
	m_WebSocket = std::make_unique<CWebSocket>();
}
CBootstrap::~CBootstrap()
{
}
void CBootstrap::Run()
{
	m_Hooks->HookAll();
	m_WebSocket->Run(5566);
}