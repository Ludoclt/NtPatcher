#ifndef NTPATCH_H
#define NTPATCH_H

#include "types.h"

#define CMD_BASE_SIZE 24
#define RET_CMD_SIZE 13
#define CUSTOM_STACK_SIZE 128

#ifdef __cplusplus
extern "C"
{
#endif

    size_t payload_offset = sizeof(DWORD_PTR);
    size_t save_state_offset = 2 * sizeof(DWORD_PTR) + 2 * sizeof(size_t);
    size_t state_dump_offset = 2 * sizeof(DWORD_PTR) + 2 * sizeof(size_t) + sizeof(BOOL);
    size_t dump_offset = 2 * sizeof(DWORD_PTR) + 2 * sizeof(size_t) + sizeof(BOOL) + sizeof(BYTE *);

    void patch_memory(patched_memory_block_t *patched_memory_block);
    void hook_function(hooked_function_t *hooked_function);

#ifdef __cplusplus
}
#endif

#endif