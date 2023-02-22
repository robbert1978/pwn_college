xor rax, rax
mov rax, 0x67616c662f
push rax
push rsp

mov rdi, [RSP + 0] 
mov rax, 0x4
syscall ; Syscall
add RSP, 16

