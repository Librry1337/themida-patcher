
#include <Windows.h>


#include <cstdio>
#include "../antidebugCRA/minhook/MinHook.h"
#include <Windows.h>
#include <cstdio>


typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessDebugFlags = 31,
    ProcessDebugObjectHandle = 30,
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS {
    ThreadHideFromDebugger = 0x11,
} THREADINFOCLASS;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef LONG NTSTATUS;

typedef NTSTATUS(NTAPI* tNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tNtSetInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG);



typedef BOOL(WINAPI* tGetThreadContext)(HANDLE, LPCONTEXT);
typedef NTSTATUS(NTAPI* tNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* tNtSetInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG);

tGetThreadContext oGetThreadContext = nullptr;
tNtQueryInformationProcess oNtQueryInformationProcess = nullptr;
tNtSetInformationThread oNtSetInformationThread = nullptr;

// GetThreadContext
BOOL WINAPI hkGetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
    BOOL ret = oGetThreadContext(hThread, lpContext);
    if (ret && lpContext)
    {
        lpContext->Dr0 = 0;
        lpContext->Dr1 = 0;
        lpContext->Dr2 = 0;
        lpContext->Dr3 = 0;
        lpContext->Dr6 = 0;
        lpContext->Dr7 = 0;
        std::printf("[aethereal] GetThreadContext patched debug registers\n");
    }
    return ret;
}

//  NtQueryInformationProcess
NTSTATUS NTAPI hkNtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS status = STATUS_SUCCESS;

    switch (ProcessInformationClass)
    {
    case ProcessDebugPort:
        std::printf("[aethereal] NtQueryInformationProcess: ProcessDebugPort patched\n");
        if (ProcessInformation && ProcessInformationLength >= sizeof(HANDLE))
            *(HANDLE*)ProcessInformation = NULL;
        if (ReturnLength)
            *ReturnLength = sizeof(HANDLE);
        break;

    case ProcessDebugFlags:
        std::printf("[aethereal] NtQueryInformationProcess: ProcessDebugFlags patched\n");
        if (ProcessInformation && ProcessInformationLength >= sizeof(ULONG))
            *(ULONG*)ProcessInformation = 0;
        if (ReturnLength)
            *ReturnLength = sizeof(ULONG);
        break;

    case ProcessDebugObjectHandle:
        std::printf("[aethereal] NtQueryInformationProcess: ProcessDebugObjectHandle patched\n");
        if (ProcessInformation && ProcessInformationLength >= sizeof(HANDLE))
            *(HANDLE*)ProcessInformation = NULL;
        if (ReturnLength)
            *ReturnLength = sizeof(HANDLE);
        break;

    default:
        status = oNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
            ProcessInformationLength, ReturnLength);
        break;
    }

    return status;
}

//  NtSetInformationThread
NTSTATUS NTAPI hkNtSetInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength)
{
    if (ThreadInformationClass == ThreadHideFromDebugger)
    {
        std::printf("[aethereal] NtSetInformationThread: ThreadHideFromDebugger patched\n");
        return STATUS_SUCCESS;
    }
    return oNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

bool HookFunctions()
{
    if (MH_Initialize() != MH_OK)
        return false;

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hKernel32 || !hNtdll)
        return false;

    // GetThreadContext
    void* pGetThreadContext = GetProcAddress(hKernel32, "GetThreadContext");
    if (pGetThreadContext)
    {
        if (MH_CreateHook(pGetThreadContext, &hkGetThreadContext, reinterpret_cast<LPVOID*>(&oGetThreadContext)) != MH_OK)
            return false;
        if (MH_EnableHook(pGetThreadContext) != MH_OK)
            return false;
    }

    // NtQueryInformationProcess
    void* pNtQueryInformationProcess = GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (pNtQueryInformationProcess)
    {
        if (MH_CreateHook(pNtQueryInformationProcess, &hkNtQueryInformationProcess, reinterpret_cast<LPVOID*>(&oNtQueryInformationProcess)) != MH_OK)
            return false;
        if (MH_EnableHook(pNtQueryInformationProcess) != MH_OK)
            return false;
    }

    // NtSetInformationThread
    void* pNtSetInformationThread = GetProcAddress(hNtdll, "NtSetInformationThread");
    if (pNtSetInformationThread)
    {
        if (MH_CreateHook(pNtSetInformationThread, &hkNtSetInformationThread, reinterpret_cast<LPVOID*>(&oNtSetInformationThread)) != MH_OK)
            return false;
        if (MH_EnableHook(pNtSetInformationThread) != MH_OK)
            return false;
    }

    return true;
}

void UnhookFunctions()
{
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        if (!HookFunctions())
        {
            std::printf("[aethereal] Failed to set hooks\n");
            return FALSE;
        }
        std::printf("[aethereal] Hooks installed successfully\n");
        break;

    case DLL_PROCESS_DETACH:
        UnhookFunctions();
        std::printf("[aethereal] Hooks removed\n");
        break;
    }
    return TRUE;
}
