// dllmain.cpp : Defines the entry point for the DLL application.
#include <windows.h>
#include "detours.h"
#include <stdio.h>
#include <iostream>

#pragma comment(linker, "/export:DetourFinishHelperProcess,@1,NONAME")

// BEGIN FUNCTION POINTERS
static void(WINAPI* TrueSleep)(DWORD dwMilliseconds) = Sleep;
static BOOL(WINAPI* TrueShowWindow)(HWND hWnd, int nCmdShow) = ShowWindow;
static BOOL(WINAPI* TrueUpdateWindow)(HWND hWnd) = UpdateWindow;
// END FUNCTION POINTERS

// BEGIN FUNCTION DEFINITIONS
void WINAPI DetourSleep(DWORD dwMilliseconds)
{
    char buf[MAX_PATH];
    sprintf_s(buf, MAX_PATH, "Detour: Sleep(%d)\n", dwMilliseconds);
    OutputDebugStringA(buf);

    TrueSleep(dwMilliseconds);
}

BOOL WINAPI DetourShowWindow(HWND hWnd, int nCmdShow)
{
    char buf[MAX_PATH];
    sprintf_s(buf, MAX_PATH, "Detour: DetourShowWindow(%p, %d)\n", hWnd, nCmdShow);
    OutputDebugStringA(buf);

    return TrueShowWindow(hWnd, nCmdShow);
}

BOOL WINAPI DetourUpdateWindow(HWND hWnd)
{
    char buf[MAX_PATH];
    sprintf_s(buf, MAX_PATH, "Detour: DetourUpdateWindow(%p)\n", hWnd);
    OutputDebugStringA(buf);

    return TrueUpdateWindow(hWnd);
}
// END FUNCTION DEFINITIONS

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    LONG error;
    (void)hModule;
    (void)lpReserved;

    if (DetourIsHelperProcess())
    {
        return TRUE;
    }

    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            DetourRestoreAfterWith();

            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());

            // BEGIN ATTACHMENTS
            {
                DetourAttach(&TrueSleep, DetourSleep);
                DetourAttach(&TrueShowWindow, DetourShowWindow);
                DetourAttach(&TrueUpdateWindow, DetourUpdateWindow);
            }
            // END ATTACHMENTS

            error = DetourTransactionCommit();
            if (error != NO_ERROR)
            {
                // Error reporting
            }
        }
        break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        break;
        case DLL_PROCESS_DETACH:
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());

            // BEGIN DEATTACHMENTS
            {
                DetourDetach(&TrueSleep, DetourSleep);
                DetourDetach(&TrueShowWindow, DetourShowWindow);
                DetourDetach(&TrueUpdateWindow, DetourUpdateWindow);
            }
            // END DEATTACHMENTS

            error = DetourTransactionCommit();
            if (error != NO_ERROR)
            {
                // Error reporting
            }
        }
        break;
    }

    return TRUE;
}

