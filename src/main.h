#include "SDK/amx/amx.h"
#include "SDK/plugincommon.h"

#ifdef WIN32
#include <Windows.h>
#else
#include <string.h>
#include <sys/mman.h>
#endif

#ifndef WIN32
typedef unsigned int DWORD;
typedef unsigned char BYTE;
#endif

void UnProtect(DWORD addr, size_t size);

typedef void(*logprintf_t)(const char* format, ...);
extern logprintf_t logprintf;
extern void* pAMXFunctions;
extern void** ppPluginData;