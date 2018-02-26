#!/usr/bin/env python

import struct
import sys
import time
from random import randint
import serial
ser = serial.Serial('/dev/ttyACM0', 57600, timeout=0.5)  # open serial port

REGS = { 0xF0 : "A", 0xF1 : "F1",
0xF2 : "F2", 0xF3 : "X", 0xF4 : "PC", 0xF5 : "PC", 0xF6 : "SP", 0xF7 :
"CPU_F", 0xF8 : "opc0", 0xF9 : "opc1", 0xFA : "opc2", 0xFB : "FB", 0xFC : "FC",
0xFD : "DAC_D", 0xFE : "CPU_SCR1", 0xFF : "CPU_SCR0"}

def get_n_resp(n):
    insync = ser.read(1) # STK_INSYNC
    # check received ack
    if insync != '\x14':
        print "read byte failed"
        print repr(insync)
        exit(1)
    data = []
    for i in range(0, n):
        data.append(ser.read(1))

    ok = ser.read(1) # STK_OK
    if ok != '\x10':
        print "read %d bytes failed" % n
        print repr(ok)
        exit(1)
    return data

def get_byte_resp():
    insync = ser.read(1) # STK_INSYNC
    # check received ack
    if insync != '\x14':
        print "read byte failed"
        print repr(insync)
        exit(1)
    data = ser.read(1)
    ok = ser.read(1) # STK_OK

    if ok != '\x10':
        print "read byte failed"
        print repr(ok)
        exit(1)
    return data

def get_empty_resp():
    insync = ser.read(1) # STK_INSYNC
    ok = ser.read(1) # STK_OK

    # check received ack
    if insync != '\x14' or ok != '\x10':
        print "Sync failed"
        print repr(insync)+" / "+repr(ok)
        exit(1)

def write_reg(reg, value):
    ser.write("\x80"+chr(reg)+chr(value)+"\x20")
    get_empty_resp()

def read_reg(reg):
    ser.write("\x79"+chr(reg)+"\x20")
    return get_byte_resp()

def read_ram(addr):
    ser.write("\x81"+chr(addr)+"\x20")
    return get_byte_resp()

def write_ram(addr, value):
    ser.write("\x82"+chr(addr)+chr(value)+"\x20")
    get_empty_resp()

def dump_regs():
    for reg in range(0xF0, 0xFF):
        print "%2s [%02X] %02X " % (REGS[reg], reg, ord(read_reg(reg)[0]))

def dump_ram(fname="dump"):
    ram = []
    for i in range(0, 256):
        data = read_ram(i)
        ram.append(data)

    with open(fname, 'wb+') as out:
        out.write("".join(ram))

def exec_opcodes(opc):
    ser.write("\x83"+opc+"\x20")
    get_empty_resp()

def identify_regs():
    val = randint(0, 255)
    print "A <= %x" % val
    write_reg(0xF0, val)
    dump_regs()
    # Helper to identify registers
    exec_opcodes("\x38\x44\x30") # ADD SP, 44
    exec_opcodes("\x01\x01\x30") # ADD A, A
    exec_opcodes("\x5C\x40\x30") # MOX X, A
    exec_opcodes("\x7D\x70\x30") # JMP 0x7030
    print "-----"
    dump_regs()

def try_romx_read():
    # Read Addr 0 with ROMX
    data = []
    for i in range(0, 8192):
        sys.stdout.flush()
        write_reg(0xF0, i>>8) # A = 0
        write_reg(0xF3, i&0xFF) # X = 0
        exec_opcodes("\x28\x30\x40") # ROMX
        byte = read_reg(0xF0)
        print "%02x" % ord(byte[0]),
        data.append(byte)
    print "\n"
    print repr(data)
    with open('flash', 'wb+') as out:
        out.write("".join(data))

def read_sig():
    print 'Reading Signature'
    ser.write("\x75\x20")
    sig = get_n_resp(2)
    print "Sig : %02X %02X" % (ord(sig[0]), ord(sig[1]))

def read_block(addr):
    ser.write("\x55"+struct.pack(">H", addr)+"\x20")
    get_empty_resp()
    res =  read_ram(0xF8)
    print "%04X: %02x" % (addr, ord(res[0]))
    return res

# Reads data from RAM @ 0x80
def read_0x80_data(addr, length):
    print "read page (0x74)"
    # Read 0x00 * 256 + 0x60 bytes
    # F == flash
    ser.write("\x74"+struct.pack('>H', length)+"\x20")
    res = ser.read(1)
    if res == "\x11":
        print "failed"
        exit(1)
    for i in range(0, length):
        data.append(ser.read(256))


# get in sync with the AVR
print "syncing"
ser.write('\x30') # STK_GET_SYNC
ser.write('\x20') # STK_CRC_EOP

# receive sync ack
print "receiving sync ack"
get_empty_resp()

while True:
    time.sleep(0.1)
    print 'Entering prog mode'
    ser.write("\x50")
    res = ser.read(1)
    if res != "\x10":
        print "failed"
    else:
        break

#dump_ram("ram_read")
raw_input("fu")
# Try to checksum
ser.write("\x85")
#ser.write("\x50")
res = ser.read(1)
#print repr(get_n_resp(2))
dump_ram("ram_csum")
exit(0)
for i in range(0, 2):
    print "checksum %d" % i
    raw_input('fu')
    write_reg(0xF7, 0x0) # CPU_F = 0
    write_reg(0xF6, 0x0) # SP = 0
    write_reg(0xF4, 0x3) # PCl
    write_reg(0xF5, 0x0) # PCh
    write_ram(0xFB, 0x80) # POINTER = 80
    write_ram(0xF8, 0x3A) # KEY1 = 3A
    write_ram(0xF9, 0x3) # KEY 2 = 3
    write_ram(0xFA, i) # nb of blocks
    write_ram(0xF0, 7) # a = 7
    exec_opcodes("\x00\x30\x40")
    exit(0)
    ser.write("\x50")
    res = ser.read(1)
    dump_ram("ram_csum_%02x" % i)
