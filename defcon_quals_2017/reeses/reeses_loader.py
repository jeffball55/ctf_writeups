from ctypes import *
import idaapi

class SecHdr1(LittleEndianStructure):
	_fields_ = [
		("addr", c_uint),
		("unused4", c_uint),
		("length", c_uint),
		("offset", c_uint),
		("cls", c_uint)
	]

class SecHdr2(LittleEndianStructure):
	_fields_ = [
		("reg", c_uint),
		("value", c_uint)
	]

class ReesesHdr(LittleEndianStructure):
	_fields_ = [
		("magic", c_uint),
		("unk4", c_uint),
		("unk8", c_uint),
		("sec1hdr_off", c_uint),
		("sec2hdr_off", c_uint),
		("nsec1", c_ushort),
		("nsec2", c_ushort),
		("signbytes", c_uint),
		("not_entry", c_uint)
	]
	_pack_ = 1


def accept_file(f, n):
	if n > 0:
		return 0
	f.seek(0)
	if f.read(2) != "AJ":
		return 0
	return "Python reeses loader"

def load_file(f, neflags, fmt):
	idaapi.set_processor_type("mipsl", SETPROC_ALL|SETPROC_FATAL)

	f.seek(0)
	rh = ReesesHdr()
	# BOGUS because ida gives you a "file like" object... f.readinto(rh)
	stsz = sizeof(rh)
	fbytes = f.read(stsz)
	fit = min(len(fbytes), stsz)
	memmove(addressof(rh), fbytes, fit)

	print "reeses hdr done"

	# get sections
	f.seek(rh.sec1hdr_off)
	for i in range(0,rh.nsec1):
		curseg = SecHdr1()
		# SUPER BOGUS f.readinto(curseg)
		stsz = sizeof(curseg)
		fbytes = f.read(stsz)
		fit = min(len(fbytes), stsz)
		memmove(addressof(curseg), fbytes, fit)

		if curseg.cls == 1:
			print "reeses: add segment 0x%08x, length=%d" % (curseg.addr, curseg.length)
			f.file2base(curseg.offset, curseg.addr, curseg.addr+curseg.length, 1)
			idaapi.add_segm(0, curseg.addr, curseg.addr+curseg.length, "seg%d"%i, "CODE")
		print "reeses: seg %d done" % i
	print "reeses load_file done"

	#print "entry pt is 0x%08x" % rh.entry
	return 1

def print_struct(s):
	for field_name, field_type in s._fields_:
		print field_name, getattr(s, field_name)

def standalone_test():
	f = open("sample1", "r")
	hdr = ReesesHdr()
	f.readinto(hdr)
	print_struct(hdr)
	load_file(f,0,0)
	f.close()

