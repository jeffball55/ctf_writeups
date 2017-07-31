import struct, os, string
from binaryninja import (
    Architecture, RegisterInfo, InstructionInfo,
    InstructionTextToken, InstructionTextTokenType, InstructionTextTokenContext,
    BranchType,
    LowLevelILOperation, LLIL_TEMP,
    LowLevelILLabel,
    FlagRole,
    LowLevelILFlagCondition,
    log_error,
    CallingConvention,
    interaction
)

# Try to import our assembler.  If it's missing don't error out
try:
  import asm
except:
  asm = None

#########################################################################################
## Memory decoding ######################################################################
#########################################################################################

# Please don't judge my awful bit reading/converting code.  This was done in a mad rush
# late at night on Thursday.

class ByteStream(object):

  def __init__(self):
    self.bytes = []

  def add_bytes(self, new_bytes, size):
    self.bytes.append((new_bytes, size))

  def _add_byte(self, stream, current_byte, current_num_bits, new_byte):
    num_new_bits = 8 - current_num_bits
    offset_to_bits = 9 - num_new_bits
    mask = ((1 << num_new_bits) - 1) << (offset_to_bits)
    new_bits = ((new_byte & mask) >> offset_to_bits)
    new_stream_byte = (current_byte << num_new_bits) | new_bits
    stream += chr(new_stream_byte)

    num_bits_left = 9 - num_new_bits
    if num_bits_left == 8:
      stream += chr(new_byte & 0xff)
      new_current_num_bits = 0
      new_current_byte = 0
    else:
      leftover_bits_mask = ((1 << num_bits_left) - 1)
      new_current_num_bits = num_bits_left
      new_current_byte = new_byte & leftover_bits_mask

    return stream, new_current_byte, new_current_num_bits

  def to_byte_stream(self):
    current_byte = 0
    current_num_bits = 0
    stream = ""

    for byte, size in self.bytes:

      if size == 3:
        middle = (byte >> 9)  & 0x1ff
        least  =  byte        & 0x1ff
        most   = (byte >> 18) & 0x1ff

        stream, current_byte, current_num_bits = self._add_byte(stream, current_byte, current_num_bits, middle)
        stream, current_byte, current_num_bits = self._add_byte(stream, current_byte, current_num_bits, most)
        stream, current_byte, current_num_bits = self._add_byte(stream, current_byte, current_num_bits, least)

      elif size == 2:
        middle = (byte >> 9)  & 0x1ff
        least  =  byte        & 0x1ff

        stream, current_byte, current_num_bits = self._add_byte(stream, current_byte, current_num_bits, middle)
        stream, current_byte, current_num_bits = self._add_byte(stream, current_byte, current_num_bits, least)

      elif size == 1:
        stream, current_byte, current_num_bits = self._add_byte(stream, current_byte, current_num_bits, byte)

    if current_num_bits != 0:
      stream += chr(current_byte)

    return stream

  def _parse_byte(self, stream, current_byte, current_num_bits):
    num_new_bits = 9 - current_num_bits

    need_extra_bit = 0
    if num_new_bits > 8:
      need_extra_bit = 1
      num_new_bits = 8

    value = 0
    if current_num_bits != 0:
      mask = (1 << current_num_bits) - 1
      value = (current_byte & mask) << num_new_bits

    offset = (8 - num_new_bits)
    mask = ((1 << num_new_bits) - 1) << offset
    new_byte = (ord(stream[0]) & mask) >> offset
    value |= new_byte

    current_byte = ord(stream[0])
    current_num_bits = 8 - num_new_bits
    stream = stream[1:]

    if need_extra_bit:
      current_byte = ord(stream[0])
      current_num_bits = 7
      value = (value << 1) | ((current_byte >> 7) & 1)
      stream = stream[1:]

    return stream, current_byte, current_num_bits, value


  def add_from_byte_stream(self, stream, sizes):
    current_byte = 0
    current_num_bits = 0
    for size in sizes:

      if size == 3:
        stream, current_byte, current_num_bits, middle = self._parse_byte(stream, current_byte, current_num_bits)
        stream, current_byte, current_num_bits, most = self._parse_byte(stream, current_byte, current_num_bits)
        stream, current_byte, current_num_bits, least = self._parse_byte(stream, current_byte, current_num_bits)
        value = (most << 18) | (middle << 9) | least

      if size == 2:
        stream, current_byte, current_num_bits, least = self._parse_byte(stream, current_byte, current_num_bits)
        stream, current_byte, current_num_bits, most = self._parse_byte(stream, current_byte, current_num_bits)
        value = (most << 9) | least

      elif size == 1:
        stream, current_byte, current_num_bits, value = self._parse_byte(stream, current_byte, current_num_bits)

      self.bytes.append((value, size))


FILENAME = None
def get_filename():
  global FILENAME
  if FILENAME == None:
    FILENAME = os.getenv("BINARY_NINJA_FILENAME")
    if FILENAME == None:
      FILENAME = interaction.get_open_filename_input("File to disassemble (please select it again)")
  return FILENAME

def read_file(filename):
  fd = open(filename, "rb")
  contents = fd.read()
  fd.close()
  return contents

FILE_BYTE_STREAM = None
def make_file_contents():
  global FILE_BYTE_STREAM

  contents = read_file(get_filename())
  FILE_BYTE_STREAM = ByteStream()
  num_bytes = (len(contents) * 8) / 9
  FILE_BYTE_STREAM.add_from_byte_stream(contents, [1]*num_bytes)

def rewrite_file():
  global FILE_BYTE_STREAM
  global FILENAME
  if FILE_BYTE_STREAM == None or FILENAME == None:
    make_file_contents()

  contents = FILE_BYTE_STREAM.to_byte_stream()
  fd = open(FILENAME, "wb")
  fd.write(contents)
  fd.close()

def read_memory_value(address, size):
  global FILE_BYTE_STREAM
  if FILE_BYTE_STREAM == None:
    make_file_contents()

  if address + size > len(FILE_BYTE_STREAM.bytes): # it's beyond the end of the file
    return None

  if size == 1:
    value  = FILE_BYTE_STREAM.bytes[address][0]
  elif size == 2:
    least = FILE_BYTE_STREAM.bytes[address][0]
    most  = FILE_BYTE_STREAM.bytes[address+1][0]
    value = (most << 9) | least
  elif size == 3:
    middle = FILE_BYTE_STREAM.bytes[address][0]
    most   = FILE_BYTE_STREAM.bytes[address+1][0]
    least  = FILE_BYTE_STREAM.bytes[address+2][0]
    value = (most << 18) | (middle << 9) | least
  elif size == 4:
    first = read_memory_value(address, 3)
    second = read_memory_value(address + 3, 1)
    if first == None or second == None:
      return None
    value = (first << 9) | second
  elif size == 6:
    first = read_memory_value(address, 3)
    second = read_memory_value(address + 3, 3)
    if first == None or second == None:
      return None
    value = (first << 27) | second
  return value

MIN_STRING_SIZE = 1
MAX_STRING_SIZE = 75
def read_string(address):
  global MIN_STRING_SIZE, MAX_STRING_SIZE, FILE_BYTE_STREAM

  new_string = ""
  while len(new_string) < MAX_STRING_SIZE and address < len(FILE_BYTE_STREAM.bytes):
    orig_string = new_string
    new_char = read_memory_value(address, 1)
    address += 1
    if new_char == None or new_char > 255:
      break
    new_string += chr(new_char)
    if not all(ord(c) < 127 and c in string.printable for c in new_string):
      new_string = orig_string
      break

  if len(new_string) < MIN_STRING_SIZE:
    return None
  if len(new_string) >= MAX_STRING_SIZE:
    new_string += "..."
  
  return new_string

#########################################################################################
## Instruction decoding #################################################################
#########################################################################################

def make_operand_token(operand_type, reg, value):
  if operand_type == REGISTER_MODE:
    return InstructionTextToken(InstructionTextTokenType.RegisterToken, reg)
  elif operand_type == IMMEDIATE_MODE:
    return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(int(value)), value)
  elif operand_type == CODE_REF_MODE:
    return InstructionTextToken(InstructionTextTokenType.CodeRelativeAddressToken, hex(int(value)), value, address = value, size = 3)

def mask(num):
  return (1 << num) - 1

def get_bits(value, value_size, start, end):
  return (value >> (value_size - (end + 1))) & mask(end - start + 1)

class Inst(object):
  add_commas = True

  def __init__(self, addr, opcode, name):
    self.addr = addr
    self.opcode = opcode
    self.name = name.upper()

  def get_name(self):
    return self.name.lower()

  def add_branches(self, info):
    pass

  def get_bits(self, start, end):
    return get_bits(self.opcode, self.SIZE * 9, start, end)

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    raise RuntimeError("Not Implemented")

class Inst54bit(Inst):
  SIZE = 6
  def conditional_sets_flags(self):
    return 0

class Inst36bit(Inst):
  SIZE = 4
  def conditional_sets_flags(self):
    return 0

class Inst27bit(Inst):
  SIZE = 3
  def conditional_sets_flags(self):
    return self.get_bits(26, 26) != 0

class Inst18bit(Inst):
  SIZE = 2
  def conditional_sets_flags(self):
    return 0

class ra_rb_im(Inst27bit):
  """
    ADCI ADCIM ADI ADIM ANI DVI DVIM DVIS DVISM MDI MDIM MDIS MDISM MUI MUIM MUIS MUISM ORI
    RLI RLIM RRI RRIM SAI SAIM SBCI SBCIM SBI SBIM SLI SLIM SRI SRIM XRI
  """

  def get_operands(self):
    reg0 = self.get_bits(7, 11)
    reg1 = self.get_bits(12, 16)
    imm = self.get_bits(17, 23)
    return reg0, reg1, imm

  def get_operand_tokens(self):
    operands = self.get_operands()
    tokens = []
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None))
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None))
    tokens.append(make_operand_token(IMMEDIATE_MODE, None, operands[2]))
    return tokens

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 6) == int(values[0],2) and get_bits(instruction, 27, 24, 25) == int(values[1],2):
      return cls(addr, instruction, name)
    return None

class ra_rb_rc(Inst27bit):
  """
  AD ADC ADCM ADF ADFM ADM AN ANM DMT DV DVF DVFM DVM DVS DVSM MD MDF MDFM MDM MDS MDSM MU MUF MUFM
  MUM MUS MUSM OR ORM RL RLM RR RRM SA SAM SB SBC SBCM SBF SBFM SBM SL SLM SR SRM XR XRM
  """

  def get_operands(self):
    reg0 = self.get_bits(7,11)
    reg1 = self.get_bits(12,16)
    reg2 = self.get_bits(17,21)
    return reg0, reg1, reg2

  def get_operand_tokens(self):
    operands = self.get_operands()
    tokens = []
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None))
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None))
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[2]], None))
    return tokens

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 6) == int(values[0],2) and get_bits(instruction, 27, 22, 25) == int(values[1],2):
      return cls(addr, instruction, name)
    return None

class ra_rb_me(Inst27bit):
  """ SMP """

  def get_operands(self):
    reg0 = self.get_bits(7, 11)
    reg1 = self.get_bits(12, 16)
    memflag = self.get_bits(18, 19)
    return reg0, reg1, memflag

  def get_operand_tokens(self):
    mem_names = [ "N", "R", "RW", "E" ]
    operands = self.get_operands()
    tokens = []
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None))
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None))
    tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, mem_names[operands[2]]))
    return tokens

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if (
        get_bits(instruction, 27, 0, 6) == int(values[0],2) and
        get_bits(instruction, 27, 17, 17) == int(values[1],2) and
        get_bits(instruction, 27, 20, 26) == int(values[2],2)
      ):
      return cls(addr, instruction, name)
    return None

class no_re(Inst18bit):
  """ DBRK HT IR RE WT """

  def get_operands(self):
    return []

  def get_operand_tokens(self):
    return []

  def add_branches(self, info):
    if self.name in ["RE", "IR"]:
      info.add_branch(BranchType.FunctionReturn)

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if instruction == int(values[0],2):
      return cls(addr, instruction, name)
    return None

class co(Inst27bit):
  """ B C """

  def get_operands(self):
    offset = self.opcode & 0xffff
    if self.opcode & 0x10000 != 0: # signed value
      offset = -(0x10000 - offset)
    return self.addr + offset,

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ make_operand_token(CODE_REF_MODE, None, operands[0]) ]

  def get_cond_name(self):
    cond = self.get_bits(6, 9)
    return COND_NAMES[cond]

  def get_name(self):
    cond_name = self.get_cond_name()
    return self.name.lower() + cond_name

  def add_branches(self, info):
    target = self.get_operands()[0]
    if self.get_cond_name() == "":
      if self.name == "C":
        info.add_branch(BranchType.CallDestination, target)
      elif self.name == "B":
        info.add_branch(BranchType.UnconditionalBranch, target)
    else:
      if self.name == "C":
        info.add_branch(BranchType.CallDestination, target)
      elif self.name == "B":
        info.add_branch(BranchType.TrueBranch, target)
        info.add_branch(BranchType.FalseBranch, self.addr + self.SIZE)

  def conditional_sets_flags(self):
    return 0

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 5) == int(values[0],2):
      return cls(addr, instruction, name)
    return None

class co_ra(Inst18bit):
  """ BR CR """

  def get_operands(self):
    reg = self.get_bits(10, 14)
    return reg,

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None) ]

  def get_cond_name(self):
    cond = self.get_bits(6, 9)
    return COND_NAMES[cond]

  def get_name(self):
    cond_name = self.get_cond_name()
    return self.name.lower() + cond_name

  def add_branches(self, info):
    target = self.get_operands()[0]
    if self.get_cond_name() == "":
      if self.name == "CR":
        info.add_branch(BranchType.IndirectBranch, target)
      elif self.name == "BR":
        info.add_branch(BranchType.CallDestination, target)
    else:
      if self.name == "CR":
        info.add_branch(BranchType.CallDestination, target)
      elif self.name == "BR":
        info.add_branch(BranchType.TrueBranch, target)
        info.add_branch(BranchType.FalseBranch, self.addr + self.SIZE)

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 18, 0, 5) == int(values[0],2) and get_bits(instruction, 18, 15, 17) == int(values[1], 2):
      return cls(addr, instruction, name)
    return None

class lo(Inst36bit):
  """ BRA BRR CAA CAR """

  def is_relative(self):
    return self.name in ["BRR", "CAR"]

  def get_operands(self):
    addr = self.get_bits(9, 35)
    if self.is_relative():
      is_negative = addr & (1 << 26)
      addr &= mask(26)
      if is_negative:
        addr = -((1 << 26) - addr)
      addr += self.addr

    return addr,

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [ make_operand_token(CODE_REF_MODE, None, operands[0]) ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 36, 0, 8) == int(values[0],2):
      return cls(addr, instruction, name)
    return None

  def add_branches(self, info):
    offset = self.get_operands()[0]
    if self.name in ["BRA", "BRR"]:
      info.add_branch(BranchType.UnconditionalBranch, offset)
    elif self.name in ["CAA", "CAR"]:
      info.add_branch(BranchType.CallDestination, offset)

class ra_im(Inst27bit):
  """ CMI CMIM """

  def get_operands(self):
    reg = self.get_bits(8, 12)
    imm = self.get_bits(13, 26)
    return reg, imm

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(IMMEDIATE_MODE, None, operands[1]),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 7) == int(values[0],2):
      return cls(addr, instruction, name)
    return None

  def conditional_sets_flags(self):
    return 0


class ra_im_al(Inst27bit):
  """ MH ML MS """

  def get_operands(self):
    reg = self.get_bits(5, 9)
    if self.name == "MS":
      imm = self.get_bits(11, 26)
      if self.get_bits(10, 10): # Signed bit
        imm = -((1 << 16) - imm)
    else:
      imm = self.get_bits(10, 26)

    return reg, imm

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(IMMEDIATE_MODE, None, operands[1]),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 4) == int(values[0],2):
      return cls(addr, instruction, name)
    return None

  def conditional_sets_flags(self):
    return 0


class ra_no_fl(Inst18bit):
  """ DI EI RF SF """

  def get_operands(self):
    reg = self.get_bits(12, 16)
    return reg,

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 18, 0, 11) == int(values[0],2) and get_bits(instruction, 18, 17, 17) == int(values[1],2):
      return cls(addr, instruction, name)
    return None


class ra_rb_lo_op(Inst27bit):
  """ BF BFM NG NGF NGFM NGM NT NTM """

  def get_operands(self):
    reg1 = self.get_bits(9, 13)
    reg2 = self.get_bits(14, 18)
    return reg1, reg2

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 8) == int(values[0],2) and get_bits(instruction, 27, 19, 25) == int(values[1],2):
      return cls(addr, instruction, name)
    return None


class ra_rb_lo_ve_no_fl(Inst27bit):
  """ FTI FTIM ITF ITFM """

  def get_operands(self):
    reg1 = self.get_bits(9, 13)
    reg2 = self.get_bits(14, 18)
    return reg1, reg2

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 27, 0, 8) == int(values[0],2) and get_bits(instruction, 27, 19, 26) == int(values[1],2):
      return cls(addr, instruction, name)
    return None

  def conditional_sets_flags(self):
    return 0


class ra_rb_lo_ve_no_fl_al(Inst27bit):
  """ RMP SES SEW ZES ZEW """

  def get_operands(self):
    reg1 = self.get_bits(12,16)
    reg2 = self.get_bits(17,21)
    return reg1, reg2

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if (get_bits(instruction, 27, 0, 11) == int(values[0], 2) and
      get_bits(instruction, 27, 22, 26) == int(values[1], 2)):
      return cls(addr, instruction, name)
    return None

  def conditional_sets_flags(self):
    return 0



class ra_rb_of_re(Inst54bit):
  """ LDS LDT LDW STS STT STW """
  add_commas = False

  def get_operands(self):
    reg1 = self.get_bits(7,11)
    reg2 = self.get_bits(12,16)
    reg_count = self.get_bits(17,21) + 1
    adjust = self.get_bits(22,23)
    offset = self.get_bits(25,50) # get the non-negative value

    if self.get_bits(24, 24): # if it's negative
      offset = -((1 << 26) - offset)
    return reg1, reg2, reg_count, adjust, offset

  def get_operand_tokens(self):
    operands = self.get_operands()
    tokens = []
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None))
    tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","))
    tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "["))
    tokens.append(make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None))
    if operands[4] != 0:
      if operands[4] < 0:
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, '-'))
        tokens.append(make_operand_token(IMMEDIATE_MODE, None, -operands[4]))
      else:
        tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, '+'))
        tokens.append(make_operand_token(IMMEDIATE_MODE, None, operands[4]))
    if operands[2] != 1:
      tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","))
      tokens.append(make_operand_token(IMMEDIATE_MODE, None, operands[2]))
    tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, "]"))
    return tokens

  def get_name(self):
    operands = self.get_operands()
    suffix = ""
    if operands[3] == 1:
      suffix = "i"
    elif operands[3] == 2:
      suffix = "d"
    return self.name.lower() + suffix

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if (get_bits(instruction, 54, 0, 6) == int(values[0], 2) and
      get_bits(instruction, 54, 51, 53) == int(values[1], 2)):
      return cls(addr, instruction, name)
    return None



class ra_rb_sh_ve(Inst18bit):
  """ CM CMF CMFM CMM """

  def get_operands(self):
    reg1 = self.get_bits(8,12)
    reg2 = self.get_bits(13,17)
    return reg1, reg2

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[1]], None),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if get_bits(instruction, 18, 0, 7) == int(values[0], 2):
      return cls(addr, instruction, name)
    return None



class ra_wi_fl(Inst27bit):
  """ RND RNDM """

  def get_operands(self):
    reg1 = self.get_bits(9,13)
    return reg1,

  def get_operand_tokens(self):
    operands = self.get_operands()
    return [
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
    ]

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    if (get_bits(instruction, 27, 0, 8) == int(values[0], 2)
      and get_bits(instruction, 27, 14, 25) == int(values[1], 2)):
      return cls(addr, instruction, name)
    return None


class la(Inst54bit):
  """ A combo of ML and MH """
  add_commas = True

  def __init__(self, addr, mh, ml):
    self.addr = addr
    self.reg = mh.get_operands()[0]
    self.mh = mh
    self.ml = ml
    self.name = "LA"

  def get_operands(self):
    ml_value = self.ml.get_operands()[1]
    mh_value = self.mh.get_operands()[1]

    value = (mh_value << 10) | (ml_value & 0x3ff)
    return [self.reg, value]

  def get_operand_tokens(self):
    operands = self.get_operands()
    tokens = [
      make_operand_token(REGISTER_MODE, REGISTER_NAMES[operands[0]], None),
      make_operand_token(CODE_REF_MODE, None, operands[1])
    ]
    string = read_string(operands[1])
    if string != None:
      tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " \"" + string + "\""))
    return tokens

  @staticmethod
  def decode(cls, name, values, addr, instruction):
    first = instruction >> 27
    second = instruction & mask(27)

    ml = ra_im_al.decode(ra_im_al, "ML", Instructions["ML"][1], addr, first)
    if ml == None:
      return None
    mh = ra_im_al.decode(ra_im_al, "MH", Instructions["MH"][1], addr, second)
    if mh == None:
      return None

    # Make sure they're for the same register
    if mh.get_operands()[0] != ml.get_operands()[0]:
      return None
    return cls(addr, mh, ml)


Instructions = {
  'LA' : (la, []),
  'AD' : (ra_rb_rc, ['000000', '0000']),
  'ADC' : (ra_rb_rc, ['0100000', '0000']),
  'ADCI' : (ra_rb_im, ['0100000', '01']),
  'ADCIM' : (ra_rb_im, ['0100010', '01']),
  'ADCM' : (ra_rb_rc, ['0100010', '0000']),
  'ADF' : (ra_rb_rc, ['0000001', '0000']),
  'ADFM' : (ra_rb_rc, ['0000011', '0000']),
  'ADI' : (ra_rb_im, ['0000000', '01']),
  'ADIM' : (ra_rb_im, ['0000010', '01']),
  'ADM' : (ra_rb_rc, ['0000010', '0000']),
  'AN' : (ra_rb_rc, ['0010100', '0000']),
  'ANI' : (ra_rb_im, ['0010100', '01']),
  'ANM' : (ra_rb_rc, ['0010110', '0000']),
  'B' : (co, ['110000']),
  'BF' : (ra_rb_lo_op, ['101001100', '1000000']),
  'BFM' : (ra_rb_lo_op, ['101001110', '1000000']),
  'BR' : (co_ra, ['110010',"000"]),
  'BRA' : (lo, ['111000100']),
  'BRR' : (lo, ['111000000']),
  'C' : (co, ['110101']),
  'CAA' : (lo, ['111001100']),
  'CAR' : (lo, ['111001000']),
  'CM' : (ra_rb_sh_ve, ['10111000']),
  'CMF' : (ra_rb_sh_ve, ['10111010']),
  'CMFM' : (ra_rb_sh_ve, ['10111110']),
  'CMI' : (ra_im, ['10111001']),
  'CMIM' : (ra_im, ['10111101']),
  'CMM' : (ra_rb_sh_ve, ['10111100']),
  'CR' : (co_ra, ['110111', '000']),
  'DBRK' : (no_re, ['111111111111111111']),
  'DI' : (ra_no_fl, ['101000000101', '0']),
  'DMT' : (ra_rb_rc, ['0110100', '00000']),
  'DV' : (ra_rb_rc, ['0001100', '0000']),
  'DVF' : (ra_rb_rc, ['0001101', '0000']),
  'DVFM' : (ra_rb_rc, ['0001111', '0000']),
  'DVI' : (ra_rb_im, ['0001100', '01']),
  'DVIM' : (ra_rb_im, ['0001110', '01']),
  'DVIS' : (ra_rb_im, ['0001100', '11']),
  'DVISM' : (ra_rb_im, ['0001110', '11']),
  'DVM' : (ra_rb_rc, ['0001110', '0000']),
  'DVS' : (ra_rb_rc, ['0001100', '0010']),
  'DVSM' : (ra_rb_rc, ['0001110', '0010']),
  'EI' : (ra_no_fl, ['101000000100', '0']),
  'FTI' : (ra_rb_lo_ve_no_fl, ['101000101', '00000000']),
  'FTIM' : (ra_rb_lo_ve_no_fl, ['101000111', '00000000']),
  'HT' : (no_re, ['101000000011000000']),
  'IR' : (no_re, ['101000000001000000']),
  'ITF' : (ra_rb_lo_ve_no_fl, ['101000100', '00000000']),
  'ITFM' : (ra_rb_lo_ve_no_fl, ['101000110', '00000000']),
  'LDS' : (ra_rb_of_re, ['1010100', '000']),
  'LDT' : (ra_rb_of_re, ['1010110', '000']),
  'LDW' : (ra_rb_of_re, ['1010101', '000']),
  'MD' : (ra_rb_rc, ['0010000', '0000']),
  'MDF' : (ra_rb_rc, ['0010001', '0000']),
  'MDFM' : (ra_rb_rc, ['0010011', '0000']),
  'MDI' : (ra_rb_im, ['0010000', '01']),
  'MDIM' : (ra_rb_im, ['0010010', '01']),
  'MDIS' : (ra_rb_im, ['0010000', '11']),
  'MDISM' : (ra_rb_im, ['0010010', '11']),
  'MDM' : (ra_rb_rc, ['0010010', '0000']),
  'MDS' : (ra_rb_rc, ['0010000', '0010']),
  'MDSM' : (ra_rb_rc, ['0010010', '0010']),
  'MH' : (ra_im_al, ['10001']),
  'ML' : (ra_im_al, ['10010']),
  'MS' : (ra_im_al, ['10011']),
  'MU' : (ra_rb_rc, ['0001000', '0000']),
  'MUF' : (ra_rb_rc, ['0001001', '0000']),
  'MUFM' : (ra_rb_rc, ['0001011', '0000']),
  'MUI' : (ra_rb_im, ['0001000', '01']),
  'MUIM' : (ra_rb_im, ['0001010', '01']),
  'MUIS' : (ra_rb_im, ['0001000', '11']),
  'MUISM' : (ra_rb_im, ['0001010', '11']),
  'MUM' : (ra_rb_rc, ['0001010', '0000']),
  'MUS' : (ra_rb_rc, ['0001000', '0010']),
  'MUSM' : (ra_rb_rc, ['0001010', '0010']),
  'NG' : (ra_rb_lo_op, ['101001100', '0000000']),
  'NGF' : (ra_rb_lo_op, ['101001101', '0000000']),
  'NGFM' : (ra_rb_lo_op, ['101001111', '0000000']),
  'NGM' : (ra_rb_lo_op, ['101001110', '0000000']),
  'NT' : (ra_rb_lo_op, ['101001100', '0100000']),
  'NTM' : (ra_rb_lo_op, ['101001110', '0100000']),
  'OR' : (ra_rb_rc, ['0011000', '0000']),
  'ORI' : (ra_rb_im, ['0011000', '01']),
  'ORM' : (ra_rb_rc, ['0011010', '0000']),
  'RE' : (no_re, ['101000000000000000']),
  'RF' : (ra_no_fl, ['101000001100', '0']),
  'RL' : (ra_rb_rc, ['0110000', '0000']),
  'RLI' : (ra_rb_im, ['1000000', '00']),
  'RLIM' : (ra_rb_im, ['1000010', '00']),
  'RLM' : (ra_rb_rc, ['0110010', '0000']),
  'RMP' : (ra_rb_lo_ve_no_fl_al, ['1010010', '0000000000']),
  'RND' : (ra_wi_fl, ['101001100', '000001100000']),
  'RNDM' : (ra_wi_fl, ['101001110', '000001100000']),
  'RR' : (ra_rb_rc, ['0110001', '0000']),
  'RRI' : (ra_rb_im, ['1000001', '00']),
  'RRIM' : (ra_rb_im, ['1000011', '00']),
  'RRM' : (ra_rb_rc, ['0110011', '0000']),
  'SA' : (ra_rb_rc, ['0101101', '0000']),
  'SAI' : (ra_rb_im, ['0111101', '00']),
  'SAIM' : (ra_rb_im, ['0111111', '00']),
  'SAM' : (ra_rb_rc, ['0101111', '0000']),
  'SB' : (ra_rb_rc, ['0000100', '0000']),
  'SBC' : (ra_rb_rc, ['0100100', '0000']),
  'SBCI' : (ra_rb_im, ['0100100', '01']),
  'SBCIM' : (ra_rb_im, ['0100110', '01']),
  'SBCM' : (ra_rb_rc, ['0100110', '0000']),
  'SBF' : (ra_rb_rc, ['0000101', '0000']),
  'SBFM' : (ra_rb_rc, ['0000111', '0000']),
  'SBI' : (ra_rb_im, ['0000100', '01']),
  'SBIM' : (ra_rb_im, ['0000110', '01']),
  'SBM' : (ra_rb_rc, ['0000110', '0000']),
  'SES' : (ra_rb_lo_ve_no_fl_al, ['101000000111', '00000']),
  'SEW' : (ra_rb_lo_ve_no_fl_al, ['101000001000', '00000']),
  'SF' : (ra_no_fl, ['101000001011', '0']),
  'SL' : (ra_rb_rc, ['0101000', '0000']),
  'SLI' : (ra_rb_im, ['0111000', '00']),
  'SLIM' : (ra_rb_im, ['0111010', '00']),
  'SLM' : (ra_rb_rc, ['0101010', '0000']),
  'SMP' : (ra_rb_me, ['1010010', '1', '0000000']),
  'SR' : (ra_rb_rc, ['0101001', '0000']),
  'SRI' : (ra_rb_im, ['0111001', '00']),
  'SRIM' : (ra_rb_im, ['0111011', '00']),
  'SRM' : (ra_rb_rc, ['0101011', '0000']),
  'STS' : (ra_rb_of_re, ['1011000', '00']),
  'STT' : (ra_rb_of_re, ['1011010', '000']),
  'STW' : (ra_rb_of_re, ['1011001', '000']),
  'WT' : (no_re, ['101000000010000000']),
  'XR' : (ra_rb_rc, ['0011100', '0000']),
  'XRI' : (ra_rb_im, ['0011100', '01']),
  'XRM' : (ra_rb_rc, ['0011110', '0000']),
  'ZES' : (ra_rb_lo_ve_no_fl_al, ['101000001001', '00000']),
  'ZEW' : (ra_rb_lo_ve_no_fl_al, ['101000001010', '00000']),
}

REGISTER_MODE = 0
IMMEDIATE_MODE = 1
CODE_REF_MODE = 2

COND_NAMES = [
  "n", "e", "l", "le", "g", "ge", "no", "o", "ns", "s", "sl", "sle", "sg", "sge", None, ""
]

REGISTER_NAMES = [
    'r0',
    'r1',
    'r2',
    'r3',
    'r4',
    'r5',
    'r6',
    'r7',
    'r8',
    'r9',
    'r10',
    'r11',
    'r12',
    'r13',
    'r14',
    'r15',
    'r16',
    'r17',
    'r18',
    'r19',
    'r20',
    'r21',
    'r22',
    'r23',
    'r24',
    'r25',
    'r26',
    'r27',
    'r28',
    'st',
    'ra',
    'pc'
]

#########################################################################################
## Binary Ninja Architecture Class ######################################################
#########################################################################################

class CLEM(Architecture):
    name = 'clem'
    address_size = 4
    default_int_size = 3

    regs = {
        'r0': RegisterInfo('r0', 4),
        'r1': RegisterInfo('r1', 4),
        'r2': RegisterInfo('r2', 4),
        'r3': RegisterInfo('r3', 4),
        'r4': RegisterInfo('r4', 4),
        'r5': RegisterInfo('r5', 4),
        'r6': RegisterInfo('r6', 4),
        'r7': RegisterInfo('r7', 4),
        'r8': RegisterInfo('r8', 4),
        'r9': RegisterInfo('r9', 4),
        'r10': RegisterInfo('r10', 4),
        'r11': RegisterInfo('r11', 4),
        'r12': RegisterInfo('r12', 4),
        'r13': RegisterInfo('r13', 4),
        'r14': RegisterInfo('r14', 4),
        'r15': RegisterInfo('r15', 4),
        'r16': RegisterInfo('r16', 4),
        'r17': RegisterInfo('r17', 4),
        'r18': RegisterInfo('r18', 4),
        'r19': RegisterInfo('r19', 4),
        'r20': RegisterInfo('r20', 4),
        'r21': RegisterInfo('r21', 4),
        'r22': RegisterInfo('r22', 4),
        'r23': RegisterInfo('r23', 4),
        'r24': RegisterInfo('r24', 4),
        'r25': RegisterInfo('r25', 4),
        'r26': RegisterInfo('r26', 4),
        'r27': RegisterInfo('r27', 4),
        'r28': RegisterInfo('r28', 4),
        'st': RegisterInfo('st', 4),
        'ra': RegisterInfo('ra', 4),
        'pc': RegisterInfo('pc', 4),
    }

    flags = ['s', 'o', 'c', 'z']

    # The first flag write type is ignored currently.
    # See: https://github.com/Vector35/binaryninja-api/issues/513
    flag_write_types = ['', '*']

    flags_written_by_flag_write_type = {
        '*': ['s', 'o', 'c', 'z'],
    }
    flag_roles = {
        's': FlagRole.NegativeSignFlagRole,
        'o': FlagRole.OverflowFlagRole,
        'c': FlagRole.CarryFlagRole,
        'z': FlagRole.ZeroFlagRole,
    }

    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_UGE: ['c', 'z'],
        LowLevelILFlagCondition.LLFC_ULT: ['c'],
        LowLevelILFlagCondition.LLFC_SGE: ['s', 'o', 'z'],
        LowLevelILFlagCondition.LLFC_SLT: ['s', 'o'],
        LowLevelILFlagCondition.LLFC_E: ['z'],
        LowLevelILFlagCondition.LLFC_NE: ['z'],
        LowLevelILFlagCondition.LLFC_NEG: ['s'],
        LowLevelILFlagCondition.LLFC_POS: ['s']
    }

    stack_pointer = 'st'
    link_reg = 'ra'
    address_size = 3

    def find_instruction(self, addr):
      found = []
      bytes_per_size = {}
      for name, (inst_type, values) in Instructions.items():
        size = inst_type.SIZE
        if size not in bytes_per_size:
          bytes_per_size[size] = read_memory_value(addr, size)

        # If we weren't able to get the memory (we're past the end of the unpacked bytes)
        if bytes_per_size[size] == None:
          continue

        inst = inst_type.decode(inst_type, name, values, addr, bytes_per_size[size])
        if inst != None:
          found.append(inst)
      if len(found) > 1:
        for inst in found:
          if inst.name == "LA":
            return inst
        raise RuntimeError("Multiple instructions found {}".format([x.__class__.__name__ for x in found]))
      elif len(found) == 0:
        return None
      return found[0]

    def decode_instruction(self, data, addr):
        if len(data) < 4:
            return None

        instr = self.find_instruction(addr)
        if instr == None:
            log_error('[{:x}] Bad opcode'.format(addr))
            return None
        return instr

    def perform_get_instruction_info(self, data, addr):
        instr = self.decode_instruction(data, addr)
        if instr is None:
            return None

        result = InstructionInfo()
        result.length = instr.SIZE
        instr.add_branches(result)

        return result

    def perform_get_instruction_text(self, data, addr):
        instr = self.decode_instruction(data, addr)
        if instr is None:
            return None

        tokens = []

        instruction_text = instr.get_name()
        if instr.conditional_sets_flags():
            instruction_text += '.'

        tokens = [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, '{:7s}'.format(instruction_text))
        ]
        operand_tokens = instr.get_operand_tokens()
        if instr.add_commas:
          for i in range(len(operand_tokens)):
            tokens.append(operand_tokens[i])
            if i != len(operand_tokens) - 1:
              tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","))
        else:
          tokens.extend(operand_tokens)

        return tokens, instr.SIZE

    def perform_get_instruction_low_level_il(self, data, addr, il):
      return None

    def perform_assemble(self, code, addr):
      global FILE_BYTE_STREAM
      if FILE_BYTE_STREAM == None:
        make_file_contents()

      new_insts = asm.asm(code)
      num_bytes_changed = sum([len(x) for x in new_insts])

      # Update FILE_BYTE_STREAM
      for new_inst in new_insts:
        for new_byte in new_inst:
          FILE_BYTE_STREAM.bytes[addr] = (new_byte, 1)
          addr += 1

      # Rewrite the input file
      if num_bytes_changed != 0:
        rewrite_file()

       # Give binja something so it reloads the instructions
      return ("A" * num_bytes_changed, "")

    def perform_convert_to_nop(self, data, addr):
      # There's no NOP instruction, so do an AND with r0 without flag update
      bytes_changed, error = self.perform_assemble("AN r0, r0, r0", addr)
      return bytes_changed

class DefaultCallingConvention(CallingConvention):
    name = 'default'
    int_arg_regs = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8']
    int_return_reg = 'r0'

#########################################################################################
## Register the architecture ############################################################
#########################################################################################

CLEM.register()
arch = Architecture['clem']
try:
  arch.register_calling_convention(DefaultCallingConvention(arch, "default")) # dev version
except:
  arch.register_calling_convention(DefaultCallingConvention(arch)) # prod version
standalone = arch.standalone_platform
standalone.default_calling_convention = arch.calling_conventions['default']

