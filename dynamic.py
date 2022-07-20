from capstone import *
from pwn import *
from unicorn import *
from unicorn.x86_const import *

code=open(sys.argv[1], "rb").read()
cs=Cs( CS_ARCH_X86 , CS_MODE_32 )

mu = Uc(UC_ARCH_X86 , UC_MODE_32)
mu.mem_map(0x0 , 1024*1024)
mu.mem_write(0x0, code )
mu.reg_write( UC_X86_REG_ESP , 0x1000) 

def hook_code (uc, address , size , user_data ):
  global cs
  global tmp
  ins=uc.mem_read( address , size )
  for i in cs.disasm(ins , 0):
      print ("| hook at 0x{:03x} | size={} | {}  {} |".format(address,size,i.mnemonic,i.op_str))

print('TO DECODE:',mu.mem_read(0x20 ,len(code[0x20:])))
mu.hook_add(UC_HOOK_CODE, hook_code)
mu.emu_start(0x7, 0x20)
print('RESULT:',mu.mem_read(0x20, len(code[0x20:])))