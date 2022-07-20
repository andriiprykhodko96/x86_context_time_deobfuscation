from pwn import *

def bytes_to_word(b1,b2,b3,b4):
  return b1 + b2*0x100 + b3*0x10000 + b4*0x1000000

code = read(sys.argv[1])

sm = (len(code)-2)%4
add = (4-sm)%4

print('TO DECODE:',code[0x20:])	
code = bytearray(code)+b'\x00'*add

print('')
tmp = 0
eax = 0
i = 0x1e-add
if sm ==1:
	i = 0x1e+1
	
while i+add<len(code):
  was = code[i:i+4]
  tmp = bytes_to_word(code[i],code[i+1],code[i+2],code[i+3])
  tmp = tmp ^ eax
  code[i] = tmp % 0x100
  code[i+1] = tmp % 0x10000 // 0x100
  code[i+2] = tmp % 0x1000000 // 0x10000
  code[i+3] = tmp // 0x1000000
  print("before==>:{}  after=>{}  eax:{}".format(was, code[i:i+4],hex(eax)))
  i = i + 4
  if i < len(code):
    eax = (eax + bytes_to_word(code[i-4],code[i-3],code[i-2],code[i-1])) % 0x100000000
print("")
print('RESULT:',code[0x20:len(code)-add])