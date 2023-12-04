#include <windows.h>
#include <stdio.h>

#include "hooks.h"

// This file contains trash coding, do not use it as a reference for anything

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);

        InstallHooks();
    }

    return TRUE;
}
