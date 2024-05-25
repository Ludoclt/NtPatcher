#ifndef NTPATCH_TYPES_H
#define NTPATCH_TYPES_H

#include <windef.h>

typedef struct __attribute__((packed))
{
    DWORD_PTR abs_addr;
    BYTE *new_bytes;
    size_t patch_size;
    BYTE *old_bytes;
} patched_memory_block_t;

typedef patched_memory_block_t PatchedMemoryBlock;

typedef struct __attribute__((packed))
{
    DWORD_PTR abs_addr;
    DWORD_PTR payload_addr;
    size_t skip_bytes;
    size_t dump_overflow;
    BOOL save_state;
    BYTE *state_dump;
    BYTE *dump;
} hooked_function_t;

typedef hooked_function_t HookedFunction;

#endif