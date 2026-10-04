/* Two processes each write 128 KiB to separate streams; no runtime libraries. */
.global _start
.text
#if defined(__x86_64__)
_start:
    mov $57, %eax
    syscall
    test %rax, %rax
    jz child
    mov $8192, %r12d
parent_loop:
    mov $1, %eax
    mov $1, %edi
    lea stdout_data(%rip), %rsi
    mov $16, %edx
    syscall
    dec %r12d
    jnz parent_loop
    mov $60, %eax
    xor %edi, %edi
    syscall
child:
    mov $8192, %r12d
child_loop:
    mov $1, %eax
    mov $2, %edi
    lea stderr_data(%rip), %rsi
    mov $16, %edx
    syscall
    dec %r12d
    jnz child_loop
    mov $60, %eax
    xor %edi, %edi
    syscall
#elif defined(__aarch64__)
_start:
    mov x8, #220
    mov x0, #17
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    svc #0
    cbz x0, child
    mov x19, #1
    adr x20, stdout_data
    b write_stream
child:
    mov x19, #2
    adr x20, stderr_data
write_stream:
    mov x21, #8192
write_loop:
    mov x0, x19
    mov x1, x20
    mov x2, #16
    mov x8, #64
    svc #0
    subs x21, x21, #1
    b.ne write_loop
    mov x0, #0
    mov x8, #93
    svc #0
#else
#error unsupported synthetic fixture architecture
#endif
stdout_data: .ascii "stdout-sentinel\n"
stderr_data: .ascii "stderr-sentinel\n"
.section .note.GNU-stack,"",@progbits
