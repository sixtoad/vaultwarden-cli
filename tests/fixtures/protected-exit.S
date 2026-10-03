/* Harmless native Linux fixture: require explicit argv and empty environment. */
#if defined(__x86_64__)
.global _start
.text
_start:
    cmpq $2, (%rsp)
    jne bad
    mov 16(%rsp), %rax
    cmpl $0x6b72616d, (%rax) /* mark */
    jne bad
    cmpb $0, 4(%rax)
    jne bad
    cmpq $0, 24(%rsp)       /* argv terminator */
    jne bad
    cmpq $0, 32(%rsp)       /* empty environment */
    jne bad
    mov $42, %edi
    jmp done
bad:
    mov $99, %edi
done:
    mov $60, %eax
    syscall
#elif defined(__aarch64__)
.global _start
.text
_start:
    ldr x0, [sp]
    cmp x0, #2
    b.ne bad
    ldr x1, [sp, #16]
    ldr w2, [x1]
    movz w3, #0x616d
    movk w3, #0x6b72, lsl #16
    cmp w2, w3
    b.ne bad
    ldrb w2, [x1, #4]
    cbnz w2, bad
    ldr x2, [sp, #24]
    cbnz x2, bad
    ldr x2, [sp, #32]
    cbnz x2, bad
    mov x0, #42
    b done
bad:
    mov x0, #99
done:
    mov x8, #93
    svc #0
#else
#error unsupported synthetic fixture architecture
#endif
.section .note.GNU-stack,"",@progbits
