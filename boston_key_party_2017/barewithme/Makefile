
shell:
	arm-none-eabi-as shellcode.s -o shellcode.o
	arm-none-eabi-objcopy -O binary --only-section=.text shellcode.o shellcode
	arm-none-eabi-objdump -d shellcode.o

