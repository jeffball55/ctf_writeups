
payload: lzss mips amd64
	python build_payload.py mips.bin amd64.bin

mips:
	mips-elf-as -EL mips.s -o mips.o
	objcopy -j .text -O binary mips.o mips.bin

amd64:
	gcc -masm=intel amd64.s -c -o amd64.o
	objcopy -j .text -O binary amd64.o amd64.bin

lzss:
	gcc lzss.c -o lzss

clean:
	rm -f *.bin *.o payload payload.lzss lzss
