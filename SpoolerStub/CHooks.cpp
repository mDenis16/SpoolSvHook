
#include <memory>

#include "CHooks.hpp"
#include <spdlog/spdlog.h>
#include "Hooking/Hooking.h"
#include "CSpoolSVHooks.hpp"
#include <Minhook.h>

CHooks::CHooks()
{
    m_SpoolSVHooks = std::make_unique<CSpoolSVHooks>();
}

CHooks::~CHooks()
{
}

void CHooks::HookAll()
{
    hook::set_base();

    spdlog::debug("Initializing hooks!");

    if (MH_Initialize() != MH_OK)
    {
        spdlog::critical("Unable to initialize Minhook library.");
        return;
    }
    m_SpoolSVHooks->EnableAll();
}