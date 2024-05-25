#include "ntpatch_api.h"

#include <fileapi.h>
#include <memoryapi.h>
#include <processthreadsapi.h>
#include <libloaderapi.h>
#include <tlhelp32.h>
#include <handleapi.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

BOOL NtP_Init(DWORD process_id)
{
    NtP_target_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (NtP_InjectDll("ntpatch.dll"))
        return TRUE;
    return FALSE;
}

BOOL NtP_InjectDll(const char *dll_path)
{
    char dll_full_path[MAX_PATH];
    GetFullPathNameA(dll_path, MAX_PATH, dll_full_path, NULL);

    void *remote_buffer = VirtualAllocEx(NtP_target_handle, NULL, sizeof(dll_full_path), MEM_COMMIT, PAGE_READWRITE);
    if (remote_buffer == NULL)
        return FALSE;

    WriteProcessMemory(NtP_target_handle, remote_buffer, dll_full_path, sizeof(dll_full_path), NULL);
    HANDLE hThread = CreateRemoteThread(NtP_target_handle, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32"), "LoadLibraryA"), remote_buffer, 0, NULL);
    if (hThread == NULL)
        return FALSE;

    return TRUE;
}

DWORD NtP_GetProcessIdByName(const char *process_name)
{
    DWORD pid = 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry) == TRUE)
    {
        do
        {
            if (strcmp((CHAR *)entry.szExeFile, process_name) == 0)
            {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry) == TRUE);
    }
    CloseHandle(snapshot);

    return pid;
}

BOOL NtP_Patch_Memory(PatchedMemoryBlock *patched_memory_block)
{
    void *remote_buffer = VirtualAllocEx(NtP_target_handle, NULL, sizeof(PatchedMemoryBlock), MEM_COMMIT, PAGE_READWRITE);
    if (remote_buffer == NULL)
        return FALSE;

    WriteProcessMemory(NtP_target_handle, remote_buffer, patched_memory_block, sizeof(PatchedMemoryBlock), NULL);
    HANDLE hThread = CreateRemoteThread(NtP_target_handle, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("ntpatch"), "patch_memory"), remote_buffer, 0, NULL);
    if (hThread == NULL)
        return FALSE;

    return TRUE;
}

BOOL NtP_Hook_Function(HookedFunction *hooked_function)
{
    void *remote_buffer = VirtualAllocEx(NtP_target_handle, NULL, sizeof(HookedFunction), MEM_COMMIT, PAGE_READWRITE);
    if (remote_buffer == NULL)
        return FALSE;

    WriteProcessMemory(NtP_target_handle, remote_buffer, hooked_function, sizeof(HookedFunction), NULL);
    HANDLE hThread = CreateRemoteThread(NtP_target_handle, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("ntpatch"), "hook_function"), remote_buffer, 0, NULL);
    if (hThread == NULL)
        return FALSE;

    return TRUE;
}