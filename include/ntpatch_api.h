#ifndef NTPATCH_API_H
#define NTPATCH_API_H

#ifdef DLL_EXPORTS
#define NTPATCH_API __declspec(dllexport)
#else
#define NTPATCH_API __declspec(dllimport)
#endif

#define ALIGN_RSP_ON_16_BYTES asm volatile("push %rbp; movq %rsp, %rbp; andq $0xF, %rbp; sub %rbp, %rsp;")
#define RESTORE_RSP_ALIGNEMENT asm volatile("add %rbp, %rsp; pop %rbp;")
#define RETURN asm volatile("jmp *%rbp;")

#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    HANDLE NtP_target_handle;

    NTPATCH_API BOOL NtP_Init(DWORD process_id);

    NTPATCH_API BOOL NtP_InjectDll(const char *dll_path);

    NTPATCH_API DWORD NtP_GetProcessIdByName(const char *process_name);

    NTPATCH_API BOOL NtP_Patch_Memory(PatchedMemoryBlock *patched_memory_block);

    NTPATCH_API BOOL NtP_Hook_Function(HookedFunction *hooked_function);

#ifdef __cplusplus
}
#endif

#endif