global _start

section .bss
tape:
    resb 30000

section .text

%macro bf_add 1
    add byte [tape + rbx], %1
%endmacro

%macro bf_sub 1
    sub byte [tape + rbx], %1
%endmacro

%macro bf_next 1
    add rbx, %1
%endmacro

%macro bf_prev 1
    sub rbx, %1
%endmacro

%macro outchar 0
    mov rdi, 1
    lea rsi, [tape + rbx]
    mov rax, 1
    syscall
%endmacro

%macro inchar 0
    mov rdi, 0
    lea rsi, [tape + rbx]
    mov rax, 0
    syscall
%endmacro

%macro jmp_beg 1
    movzx r11, byte [tape + rbx]
    test r11, r11
    jz end_%1
beg_%1:
%endmacro

%macro jmp_end 1
    movzx r11, byte [tape + rbx]
    test r11, r11
    jnz beg_%1
end_%1:
%endmacro

%macro exit 0
    mov rdi, 0
    mov rax, 60
    syscall
%endmacro

_start:
    xor rbx, rbx
    mov rdx, 1

    bf_add 10
    jmp_beg 1
    bf_next 1
    bf_add 7
    bf_next 1
    bf_add 10
    bf_next 1
    bf_add 3
    bf_next 1
    bf_add 1
    bf_prev 4
    bf_sub 1
    jmp_end 1
    bf_next 1
    bf_add 2
    outchar
    bf_next 1
    bf_add 1
    outchar
    bf_add 7
    outchar
    outchar
    bf_add 3
    outchar
    bf_next 1
    bf_add 2
    outchar
    bf_prev 2
    bf_add 15
    outchar
    bf_next 1
    outchar
    bf_add 3
    outchar
    bf_sub 6
    outchar
    bf_sub 8
    outchar
    bf_next 1
    bf_add 1
    outchar
    bf_next 1
    outchar

    exit

