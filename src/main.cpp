#include "main.h"
#include "urmem.hpp"

logprintf_t logprintf(nullptr);
void** ppPluginData(nullptr);

const DWORD PATCH_ADDR = 0x6764A;

const char* PATCH_SIG = 
"\x81\xFB\x90\x01\x00\x00"   // cmp ebx,190h // 00+
"\x81\xFB\x63\x02\x00\x00"   // cmp ebx,263h // 00+
"\x7F\x1B";                  // jg short

PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports() noexcept
{
    return SUPPORTS_VERSION/* | SUPPORTS_AMX_NATIVES | SUPPORTS_PROCESS_TICK*/;
}

PLUGIN_EXPORT bool PLUGIN_CALL Load(void** const ppData) noexcept
{
    pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];
    logprintf = (logprintf_t)(ppData[PLUGIN_DATA_LOGPRINTF]);

    urmem::sig_scanner scanner;
    urmem::address_t patch_model_address{};

    if (scanner.init(reinterpret_cast<urmem::address_t>(ppData[0]))) 
    {
        if (!scanner.find(PATCH_SIG, "xxxxxxxxxxxxx", patch_model_address) || !patch_model_address) 
        {
            logprintf("[Disable vehicle limit]: Plugin failed to load - Signature not found");
            return false;
        }
        else 
        {
            UnProtect(patch_model_address + 12, 2); // เดิม 10
            *reinterpret_cast<unsigned short*>(patch_model_address + 12) = 0x9090; // เดิม 10
            logprintf("[Disable vehicle limit]: Plugin loaded");
        }
    }
    else 
    {
        logprintf("[Disable vehicle limit]: Plugin failed to load - Scanner not inited!");
        return false;
    }
    return true;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload() noexcept
{
    logprintf("[Disable vehicle limit]: Plugin was unloaded");
}

void UnProtect(DWORD addr, size_t size) 
{
    #ifdef _WIN32
        DWORD oldProtect;
        VirtualProtect(reinterpret_cast<void*>(addr), size, PAGE_EXECUTE_READWRITE, &oldProtect);
    #else
        mprotect(reinterpret_cast<void*>((addr / 4096) * 4096), size, PROT_WRITE | PROT_READ | PROT_EXEC);
    #endif
}