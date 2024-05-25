#include "ntpatch.h"

#include <windows.h>

#ifdef DEBUG
#include <stdio.h>
#endif

extern void execute_payload(void);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpvReserved)
{
#ifdef DEBUG
    FILE *stream;
#endif
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
#ifdef DEBUG
        AllocConsole();
        freopen_s(&stream, "CONOUT$", "w", stdout);
        printf("base address: 0x%x\n", (DWORD_PTR)GetModuleHandle(NULL));
#endif
        break;
    case DLL_PROCESS_DETACH:
#ifdef DEBUG
        FreeConsole();
#endif
        break;
    }
    return TRUE;
}

void patch_memory(patched_memory_block_t *patched_memory_block)
{
    HANDLE hProcess = GetCurrentProcess();

    DWORD oldProtect;
    VirtualProtect((LPVOID)patched_memory_block->abs_addr, patched_memory_block->patch_size, PAGE_EXECUTE_READWRITE, &oldProtect);
    ReadProcessMemory(hProcess, (LPVOID)patched_memory_block->abs_addr, patched_memory_block->old_bytes, patched_memory_block->patch_size, NULL);
    WriteProcessMemory(hProcess, (LPVOID)patched_memory_block->abs_addr, patched_memory_block->new_bytes, patched_memory_block->patch_size, NULL);
    VirtualProtect((LPVOID)patched_memory_block->abs_addr, patched_memory_block->patch_size, oldProtect, NULL);

#ifdef DEBUG
    printf("successfully patched\n");
#endif
}

void hook_function(hooked_function_t *hooked_function)
{
    DWORD_PTR target_addr = hooked_function->abs_addr + hooked_function->skip_bytes;

    if (hooked_function->save_state)
        hooked_function->state_dump = VirtualAlloc(NULL, CUSTOM_STACK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    size_t cmd_size = (CMD_BASE_SIZE + hooked_function->dump_overflow);

    BYTE cmd_base[CMD_BASE_SIZE] = {
        0x51,                                                       // push rcx
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, qword
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, qword
        0xFF, 0xE0,                                                 // jmp rax
        0x58                                                        // pop rax
    };

    BYTE *cmd = malloc(cmd_size);
    memcpy(cmd, cmd_base, sizeof(cmd_base));
    for (size_t i = CMD_BASE_SIZE; i < cmd_size; i++)
        cmd[i] = 0x90;

    void *injected_address = &execute_payload;
    memcpy(&cmd[3], &hooked_function, sizeof(void *));
    memcpy(&cmd[13], &injected_address, sizeof(void *));

    BYTE ret_cmd[RET_CMD_SIZE] = {
        0x50,                                                       // push rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, qword
        0xFF, 0xE0                                                  // jmp rax
    };

    DWORD_PTR ret_addr = target_addr + cmd_size - 2;
    memcpy(&ret_cmd[3], &ret_addr, sizeof(DWORD_PTR));

    hooked_function->dump = VirtualAlloc(NULL, cmd_size + RET_CMD_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    patch_memory(&((patched_memory_block_t){target_addr, cmd, cmd_size, hooked_function->dump}));
    memcpy(hooked_function->dump + cmd_size, ret_cmd, sizeof(ret_cmd)); // add ret cmd
    VirtualProtect(hooked_function->dump, cmd_size + RET_CMD_SIZE, PAGE_EXECUTE_READ, NULL);

#ifdef DEBUG
    printf("target addr: 0x%p\n", target_addr + hooked_function->skip_bytes);
    printf("ret addr: 0x%p\n", ret_addr);
    printf("injected address: 0x%p\n", injected_address);
    printf("cmd data: 0x");
    for (int i = 0; i < cmd_size; i++)
        printf("%02x", cmd[i]);
    printf("\n");
    printf("dump address: 0x%p\n", hooked_function->dump);
#endif

    free(cmd);
}