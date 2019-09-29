# reeses revenge

The reese's revenge challenge was one of the challenges that I worked on in the DEFCON 25 Qualifier CTF with drew, crymsen,
and [joeleong](https://github.com/joeleong).

## Challenge Description

This challenge gave us a MIPS emulator "reeses" and 4 MIPS programs. A quick googling of "reeses defcon CTF" lead us to
[this page](http://www.routards.org/2013/08/defcon-21-ctf-binaries-and-environment.html) detailing the original reeses
challenge. The original reeses challenge was a signed MIPS emulator that ran had 4 programs: an echo server, a sha256
calculator, a program that obfuscates your input, and a LZSS decompression program.

This challenge reads a size from stdin (up to 100000 bytes), then attempts to read that many bytes. This process is used to
accept a MIPS ROM file from the user. The emulator validates that the ROM is signed correctly and then executes it. The author
of the challenge was kind enough to again provide 4 signed ROMs, with roughly the same purposes as the previous challenge.

## The Crypto

Recognizing that this emulator will only run signed binaries, we figured we needed to either bypass the crypto or find a
vulnerability in the MIPS programs that allowed us to gain code execution. Looking through the signature validation code, we see
that it uses public key crypto (see the key below) that is based off of OpenSSL. Looking through the `check_signature`
function at 0x42F4 (shown below), it doesn't appear that they made any obvious mistakes.

![key](https://github.com/jeffball55/ctf_writeups/blob/master/defcon_quals_2017/reeces/key.png)

![check_signature](https://github.com/jeffball55/ctf_writeups/blob/master/defcon_quals_2017/reeces/check_signature.png)

## Stage 1 Exploit

Given that we couldn't find a way to bypass the signature checks on the MIPS ROM files, we needed to gain code execution inside
the MIPS emulator by exploiting a vulnerability in one of the ROM files. As the challenge author was kind enough to provide 4
signed ROMs, we had quite a bit to reverse. The first step was to write a custom IDA loader for the MIPS ROM format, so we
could get proper address information. See the included
[reeces_loader.py](https://github.com/jeffball55/ctf_writeups/blob/master/defcon_quals_2017/reeces/reeces_loader.py) for an
IDA loader that parses the MIPS ROM header info. With that accomplished, we set about reversing each of the 4 ROMs. 

### sample2 - echo server
`sample2` was an echo server. We quickly ruled this one out due to its simplicity. The main loop is especially small and merely
reads a line and prints that line. If the line 'q' is passed in, it quits. As there wasn't much more to this program, we moved
on to the other ROMs.

### sample3 - obfuscate input
`sample3` reads a buffer, obfuscates it in the emulator, and then prints it back out. This is done by first reading a 4-byte
length, reading that number of characters, and then running the `mtc2` instruction. The `mtc2` instruction in the emulator has
been commandeered to run the obfuscation loop shown below. Checking for any bugs, we see that the length is correctly checked to
ensure it is less then the size of buffer (0x80 characters). We also ensured that there weren't any triggerable bugs in the
emulator involving the custom mtc2 operator.

![obfuscation_loop](https://github.com/jeffball55/ctf_writeups/blob/master/defcon_quals_2017/reeces/obfuscation_loop.png)

### sample4 - sha256 input
`sample4` takes a hash of any input passed to it. The program starts by building a table used in the hash calculation, as
shown in the picture below. Googling these magic values leads to the hash quickly being identified as SHA256. We then analyzed
the read loop and discovered that any input is immediately sent to the SHA256 hashing function without much other processing.
The input hashing is continued until the input line is `>>END>>`. Once the program has finished reading input, it converts the
SHA256 hash to a hexstring and prints it out.

We continued analyzing this SHA256 hash function, but decided it best to move on. We setup a fuzzer to run against this ROM,
but then decided to move on to the more complex `sample1` ROM.

![build_table.png](https://github.com/jeffball55/ctf_writeups/blob/master/defcon_quals_2017/reeces/build_table.png)

### sample1 - LZSS compress/decompress
`sample1` was the largest of the samples and the most complex. This program will compress or decompress a file using the
[LZSS](https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Storer%E2%80%93Szymanski) algorithm. In order to interact with
the program and try compressing and decompressing inputs that were not from the program originally, we searched for a lzss
example program that we could use to compress custom data. Our search lead us to this 
[example program](https://oku.edu.mie-u.ac.jp/~okumura/compression/lzss.c). However, our newly compressed inputs were unable to
be properly decompressed. After a bit of reversing, we determined that the lzss algorithm in `sample1` was not using the default
parameters for lzss. Instead, the `EI` and `EJ` parameters were set to 13 and 5 respectively (instead of the default 11 and 4).
After fixing our lzss example program, we were able to correctly compress and decompress inputs for `sample1`.

With the ability to compress our own inputs, we next tried to locate a bug in sample1 that would let us gain code execution in
the emulator. We started by generating custom inputs for the decompresser in the hopes that we'd trigger a bug there. One of the
first things we tried was an input that was significantly smaller than the decompressed output. After trying out several
different sizes, we eventually determined that if we compressed a file of 0x25ee0 bytes, we would overflow a value that was
later copied into the `$pc` register. With the ability to control the `$pc` register, we can jump into our decompressed input
and execute custom MIPS code in the emulator.

## Stage 2 Exploit
Now that we have the ability run custom MIPS code inside of the emulator, we'll need to exploit a bug in the emulator and
breakout. We continued reversing the emulator, until we found a simple stack overflow in an undocumented instruction handler
for the opcode `0xcfe00000` (shown below). Ordinarily, this instruction causes an exception and prints out some exception
instruction. However, for the `0xcfe00000` version of the instruction handler, the function copies the emulated MIPS registers
over top of the stack frame, in such a way that the registers `$a2` and `$a3` would overflow the emulator's saved `RIP`
register.

![stack_overflow.png](https://github.com/jeffball55/ctf_writeups/blob/master/defcon_quals_2017/reeces/stack_overflow.png)

## Reversing the Random Number Generator
Now that we've taken control of the emulated MIPS program and can control emulator's `RIP` register, we need to specify an
address to redirect the emulator's execution to. However, the reeses binary is PIE and uses full ASLR. Thus, we can't use any of
the code from the main reeses binary, and instead needed to look for executable memory that is at a predictable address.

While searching for an executable page in the emulator, we discovered that the `mmap` syscall allocates executable pages and
that it uses a custom randomization algorithm for determining the address of the page. The randomization algorithm, shown below,
is the same random number generation that is used in the emulated `random` syscall. Thus, if we can predict the next random
number, we will be able to determine where an executable page is in memory and can complete our exploit. 

After trying and failing to manually reverse the random number generator from within MIPS shellcode, we eventually decided that
it would be far easier and faster to ship the random number generator's state back to our laptop and reverse it there. As such,
we wrote a simple `rand`/`write` syscall loop in the emulated MIPS code and received back 128 randomly generated integers. Our
exploit code then models the `reeses` random number generator using Z3 and solves for the internal random number generator
state. Once Z3 solves for this state, our exploit generates the next random number that will be returned and writes it back to
the MIPS shellcode. The MIPS shellcode then allocates an executable page, copies our AMD64 shellcode to the new page, and
triggers the stack overflow in the emulator to redirect the emulator's code flow to our AMD64 shellcode. Our AMD64 shellcode
then spawns a shell and we can read the flag file on the server.

![get_random.png](https://github.com/jeffball55/ctf_writeups/blob/master/defcon_quals_2017/reeces/get_random.png)

