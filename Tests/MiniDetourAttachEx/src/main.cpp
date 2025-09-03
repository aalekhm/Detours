#include <windows.h>
#include <iostream>
#include <DbgHelp.h>

typedef int(WINAPI* MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);

// Will hold trampoline to original MessageBoxW
MessageBoxW_t OriginalMessageBoxW = nullptr;

// Our detour
int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    std::wcout << L"[Hooked] MessageBoxW intercepted!\n";
    return OriginalMessageBoxW(hWnd, L"[HOOKED] -> Injected", lpCaption, uType);
}

// Writes an absolute jump [mov rax, dst; jmp rax]
void WriteAbsoluteJump(BYTE* src, void* dst)
{
    DWORD oldProtect;
    VirtualProtect(src, 14, PAGE_EXECUTE_READWRITE, &oldProtect);

    src[0] = 0x48; // REX.W prefix
    src[1] = 0xB8; // MOV RAX, imm64
    *(void**)(src + 2) = dst;

    src[10] = 0xFF; // JMP RAX
    src[11] = 0xE0;

    src[12] = 0x90; // NOP
    src[13] = 0x90;

    VirtualProtect(src, 14, oldProtect, &oldProtect);
}

// Creates trampoline: copies prologue + jump back
BYTE* CreateTrampoline(BYTE* target, size_t stolenBytes)
{
    BYTE* tramp = (BYTE*)VirtualAlloc(NULL, stolenBytes + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    memcpy(tramp, target, stolenBytes); // Copy original instructions
    WriteAbsoluteJump(tramp + stolenBytes, target + stolenBytes); // Jump back

    return tramp;
}

// Detour setup
void SimpleDetourAttach(void** ppOriginal, void* pDetour)
{
    BYTE* target = (BYTE*)GetProcAddress(GetModuleHandleW(L"user32.dll"), "MessageBoxW");

    // Ideally use a disassembler to find safe instruction boundary
    size_t stolen = 14;

    BYTE* tramp = CreateTrampoline(target, stolen);
    *ppOriginal = (void*)tramp; // Save trampoline for calling original

    WriteAbsoluteJump(target, pDetour); // Patch original
}

void WhereIs(HMODULE hModule)
{
    char path[MAX_PATH];
    DWORD length = GetModuleFileNameA(hModule, path, MAX_PATH);
    if (length > 0 && length < MAX_PATH) 
    {
        std::cout << path << std::endl;
    }
}

void HookIAT(const char* moduleName, const char* funcName, void* newFunc, void** originalFunc) 
{
    HMODULE hCurrExecMod = GetModuleHandle(NULL);       // Current Executable Handle
    HMODULE hHookMod = GetModuleHandleA(moduleName);    // Hook Module Handle
    {
        WhereIs(hHookMod);
    }

    ULONG size;
    PIMAGE_IMPORT_DESCRIPTOR desc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(    hCurrExecMod, 
                                                                                            true, 
                                                                                            IMAGE_DIRECTORY_ENTRY_IMPORT, 
                                                                                            &size);

    for (; desc->Name; desc++) 
    {
        const char* dllName = (const char*)((BYTE*)hCurrExecMod + desc->Name);
        if (_stricmp(dllName, moduleName) != 0) continue;

        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hCurrExecMod + desc->FirstThunk);
        for (; thunk->u1.Function; thunk++) 
        {
            PROC* func = (PROC*)&thunk->u1.Function;
            if (*func == (PROC)GetProcAddress(hHookMod, funcName))
            {
                DWORD oldProtect;
                VirtualProtect(func, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);
                *originalFunc = (void*)(*func);
                *func = (PROC)newFunc;
                VirtualProtect(func, sizeof(void*), oldProtect, &oldProtect);
                return;
            }
        }
    }
}

int main()
{
    std::wcout << L"Before hooking...\n";
    MessageBoxW(NULL, L"Hello", L"Demo", MB_OK);

    HookIAT("user32.dll", "MessageBoxW", MyMessageBoxW, (void**)&OriginalMessageBoxW);

    // - Somtimes Crashes -> But a Simple implementation of how DetourAttachEx works
    //SimpleDetourAttach((void**)&OriginalMessageBoxW, MyMessageBoxW);
    //
    std::wcout << L"After hooking...\n";
    MessageBoxW(NULL, L"Hello", L"Demo", MB_OK);

    return 0;
}

