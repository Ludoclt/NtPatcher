.intel_syntax noprefix

.section .data
.extern payload_offset
.extern save_state_offset
.extern state_dump_offset
.extern dump_offset

.section .text

.macro custom_push ptr, val
mov [\ptr], \val
add \ptr, 8
.endm

.macro custom_pop dest, ptr
sub \ptr, 8
mov \dest, [\ptr]
.endm

.macro custom_pushaq ptr
    custom_push \ptr, rcx
    custom_push \ptr, rdx
    custom_push \ptr, rbp
    custom_push \ptr, rsi
    custom_push \ptr, rdi
    custom_push \ptr, r8
    custom_push \ptr, r9
    custom_push \ptr, r10
    custom_push \ptr, r11
.endm

.macro custom_popaq ptr
    custom_pop r11, \ptr
    custom_pop r10, \ptr
    custom_pop r9, \ptr
    custom_pop r8, \ptr
    custom_pop rdi, \ptr
    custom_pop rsi, \ptr
    custom_pop rbp, \ptr
    custom_pop rdx, \ptr
    custom_pop rcx, \ptr
.endm

.macro get_struct_value ptr, offset
    push rcx
    mov rcx, \ptr
    movabs \ptr, \offset
    add \ptr, rcx
    mov \ptr, [\ptr]
    pop rcx
.endm

.global execute_payload
execute_payload:
    mov rax, rcx
    get_struct_value rax, state_dump_offset
    custom_push rax, rcx
    pop rcx
    pushfq
    custom_push rax, rbx
    mov rbx, rax
    mov rax, [rbx-16]
    get_struct_value rax, save_state_offset
    cmp al, 1
    pop rax
    push [rbx-16]
    jne ignore_save
    custom_push rbx, rax
    custom_pushaq rbx
ignore_save:
    pop rax
    custom_push rbx, rax
    get_struct_value rax, payload_offset
    lea rbp, [rip+2]
    jmp rax
    custom_pop rax, rbx
    push rax
    get_struct_value rax, save_state_offset
    cmp al, 1
    jne ignore_restore
    custom_popaq rbx
    custom_pop rax, rbx
    push rax
    popfq
ignore_restore:
    pop rax
    pushfq
    custom_pop rbx, rbx
    get_struct_value rax, dump_offset
    popfq
    jmp rax
