/* Harmless Linux x86_64 fixture: require explicit argv and empty environment. */
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
.section .note.GNU-stack,"",@progbits
