# Binary Ninja Processor Plugin for cLEMENCy

This repository contains our [Binary Ninja](https://binary.ninja/) plugin for
the DEFCON 25 [cLEMENCy](https://github.com/legitbs/cLEMENCy) architecture.  The
architecture was designed specifically to break existing tools to level the 
playing field for DEFCON 25 CTF.

The architecture documentation and emulator was given out 24 hours before the
CTF started, so all of the teams were in a mad rush to develop the necessary
tools. Our team investigated several approaches (Ida, Binary Ninja, custom
graphviz scripts) simultaenously, but ultimately Binary Ninja turned out to be
the most usable.

## Challenges

* 9-bit bytes - Unlike normal processor architectures, cLEMENCy uses 9-bit bytes. 
Most tools are built with certain assumptions, and having 8-bit bytes is usually
one of them.  This was certainly the main challenge while developing the
processor plugin.  Our team jokingly coined the term nyte to refer to these
nine-bit bytes, and joked that a nibble on this architecture is 4.5 bits.

* [Middle-Endian](https://en.wikipedia.org/wiki/Endianness#Middle-endian) -
Unlike x86 which is little endian or MIPS which can be big or little endian,
cLEMENCy is middle endian.  For instance the 3-byte triwords, are stored to and
loaded from memory in the order: middle byte, most significant byte, least
significant byte, and 2-byte loads are: most significant byte and least
significant byte.  At little experimentation with the emulator revealed the
byte-order for 4-byte and 6-byte instructions as well.  While certainly
annoying, this feature was easily dealt with in the plugin.

## Why Binary Ninja?

While we investigated several choices, we ended up using binary ninja because
it was the simplest solution for adding processor plugin.  A look at the
example processor plugins reveals you only *really* need to define 2 functions,
`perform_get_instruction_info` and `perform_get_instruction_text`.
`perform_get_instruction_info` passes in an address and a string of bytes to
decode and asks you to return the size of the instruction at that address and
any branches that the instruction causes.  `perform_get_instruction_text` also
takes an address and a string of data bytes to decode and asks you to return a
list of tokens to display in the disassembly.

While there are certainly more you can do to define a processor plugin, these
two functions are enough to get the interactive linear and graph disassembly
that has become a staple when reversing.  We investigated implementing the
functions necessary for lifting to the low level IL, but quickly decided against
it when we saw the
[functions](https://api.binary.ninja/binaryninja.lowlevelil-module.html)
required specifying a size of the fields (which would be in the normal 8-bytes
instead of cLEMENCy's nytes).  The [Trail of Bits writeup](https://blog.trailofbits.com/2017/07/30/an-extra-bit-of-analysis-for-clemency/)
mentions they were able to get some portions added, but couldn't get the entire thing completed.

Other members of our team implemented a python based cLEMENCy assembler, which
allowed us to enable Binary Ninja's context-menu patcher.  This ended up being
very vaulable for quickly creating patches for the vulnerable services.

## The Problem

While the binary ninja API is simple, we still had to resolve the bytes vs nytes
problem. When given a cLEMENCy firmware image, it was simply a raw memory dump.
Such that the first nyte in the firmware image mapped to address 0, the second
nyte to address 1, etc.  However, the file was specifying nytes on a computer
that only understands storing/loading bytes.  Thus, the firmware images were
bit steams, such that the top 8-bits of the first nyte was in the first byte of
the file, and the last bit of the first nyte was in the second byte of the file.
Thus when binary ninja attempted to retrieve the memory at an address, it would
return the wrong memory bytes (offset by 8.0/9.0).

While we fixed this problem for the disassembly, it did result in the hex output
being completely wrong.

## The Solution

Our solution was rather simple.  We choose to completely ignore the passed in
data bytes, and instead use the passed in address to read the cLEMENCy firmware
image ourselves, unpack the bit stream, and retrieve the relevant bytes from the
firmware.  This allowed us to ensure the right memory was read and decoded.  The
rest was simply decoding the architecture and tokenizing the output.

