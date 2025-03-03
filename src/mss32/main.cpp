#include "main.h"
#include "hook.h"
#include <windows.h>

/**
 * Entry point for the DLL.
 * When the system calls the DllMain function with the DLL_PROCESS_ATTACH value, the function returns TRUE if it succeeds or FALSE if initialization fails.
 */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hook_load();
        
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
