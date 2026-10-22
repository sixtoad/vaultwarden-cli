/* Synthetic private producer: a bounded little-endian length + JSON frame on fd 3.
 * No runtime, vault access, files, network, children or inherited authority. */
.global _start
.text
#if defined(__x86_64__)
_start:
    mov $1, %eax
    mov $3, %edi
    lea frame(%rip), %rsi
    mov $(frame_end-frame), %edx
    syscall
    cmp $(frame_end-frame), %rax
    jne fail
    xor %edi, %edi
    jmp finish
fail:
    mov $9, %edi
finish:
    mov $60, %eax
    syscall
#elif defined(__aarch64__)
_start:
    mov x0, #3
    adr x1, frame
    mov x2, #(frame_end-frame)
    mov x8, #64
    svc #0
    cmp x0, #(frame_end-frame)
    b.ne fail
    mov x0, #0
    b finish
fail:
    mov x0, #9
finish:
    mov x8, #93
    svc #0
#else
#error unsupported synthetic fixture architecture
#endif
frame:
.long payload_end-payload
payload: .ascii "{\"password\":\"private-producer-sentinel\"}"
payload_end:
frame_end:
.section .note.GNU-stack,"",@progbits
