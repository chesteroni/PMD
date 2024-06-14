#include "common.hpp"

extern "C" __declspec(dllexport) void MyDllExport()
{
}

BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID)
{
    DPRINT(L"dll_template.%S\t 0x%x)", __FUNCTION__, reason);
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}