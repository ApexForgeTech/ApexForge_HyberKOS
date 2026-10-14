section .multiboot
align 8
header:
dd 0xe85250d6, 0, header_end-header
dd -(0xe85250d6 + (header_end-header))
dw 0, 0
dd 8
header_end:

section .text
bits 32
global _start
extern kernel_main
_start:
    cli
    cld
    mov esp, boot_stack_top
    mov edi, eax
    mov esi, ebx
    ; x86_64 + NX are required; unsupported CPUs fail-stop before paging.
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb halt32
    mov eax, 0x80000001
    cpuid
    and edx, (1<<29)|(1<<20)
    cmp edx, (1<<29)|(1<<20)
    jne halt32
    mov eax, pdpt
    or eax, 3
    mov [pml4], eax
    mov eax, boot_pd
    or eax, 3
    mov [pdpt], eax
    xor ecx, ecx
.map:
    mov eax, ecx
    shl eax, 21
    or eax, 0x83
    mov [boot_pd+ecx*8], eax
    inc ecx
    cmp ecx, 512
    jne .map
    mov eax, cr4
    or eax, (1<<5)|(1<<9)|(1<<10)
    mov cr4, eax
    mov eax, pml4
    mov cr3, eax
    mov ecx, 0xc0000080
    rdmsr
    or eax, (1<<8)|(1<<11)
    wrmsr
    mov eax, cr0
    and eax, ~(1<<2)
    or eax, (1<<31)|(1<<16)|(1<<1)
    mov cr0, eax
    lgdt [gdt_pointer]
    jmp 8:long_mode
halt32:
    hlt
    jmp halt32
bits 64
long_mode:
    mov ax, 16
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax,eax
    mov fs, ax
    mov gs, ax
    mov rsp, boot_stack_top
    xor rbp,rbp
    fninit
    ldmxcsr [mxcsr_initial]
    call kernel_main
    ud2

global switch_context
switch_context:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; Separate 16-byte-aligned FXSAVE areas belong to each execution context.
    fxsave64 [rdx]
    fxrstor64 [rcx]
    mov [rdi], rsp
    mov rsp, rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

extern interrupt_dispatch
%assign v 0
%rep 256
global isr_%+v
isr_%+v:
%if v != 8 && v != 10 && v != 11 && v != 12 && v != 13 && v != 14 && v != 17 && v != 21 && v != 29 && v != 30
    push qword 0
%endif
    push qword v
    jmp interrupt_common
%assign v v+1
%endrep
interrupt_common:
    cld
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rdi, [rsp+120]
    mov rsi, [rsp+128]
    mov rdx, [rsp+136]
    mov rbx,rsp
    and rsp, -16
    sub rsp,512
    fxsave64 [rsp]
    call interrupt_dispatch
    fxrstor64 [rsp]
    mov rsp,rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    add rsp,16
    iretq

section .rodata
align 4
mxcsr_initial: dd 0x1f80
align 8
gdt:
    dq 0, 0x00af9a000000ffff, 0x00cf92000000ffff
gdt_pointer:
    dw 23
    dq gdt
global isr_table
isr_table:
%assign v 0
%rep 256
    dq isr_%+v
%assign v v+1
%endrep

section .bss
align 4096
global pml4, pdpt
pml4: resb 4096
pdpt: resb 4096
boot_pd: resb 4096
align 16
boot_stack: resb 262144
boot_stack_top:
