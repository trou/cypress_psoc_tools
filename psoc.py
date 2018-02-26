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

def get_n_resp(ser, n):
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

def get_byte_resp(ser):
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

def get_empty_resp(ser):
    insync = ser.read(1) # STK_INSYNC
    ok = ser.read(1) # STK_OK

    # check received ack
    if insync != '\x14' or ok != '\x10':
        print "Sync failed"
        print repr(insync)+" / "+repr(ok)
        exit(1)

def write_reg(ser, reg, value):
    ser.write("\x80"+chr(reg)+chr(value)+"\x20")
    get_empty_resp(ser)

def read_reg(ser, reg):
    ser.write("\x79"+chr(reg)+"\x20")
    return get_byte_resp(ser)

def read_ram(ser, addr):
    ser.write("\x81"+chr(addr)+"\x20")
    return get_byte_resp(ser)

def write_ram(ser, addr, value):
    ser.write("\x82"+chr(addr)+chr(value)+"\x20")
    get_empty_resp(ser)

def dump_regs(ser):
    for reg in range(0xF0, 0xFF):
        print "%2s [%02X] %02X " % (REGS[reg], reg, ord(read_reg(ser, reg)[0]))

def dump_ram(ser, fname="dump"):
    ram = []
    for i in range(0, 256):
        data = read_ram(ser, i)
        ram.append(data)

    with open(fname, 'wb+') as out:
        out.write("".join(ram))

def exec_opcodes(ser, opc):
    ser.write("\x83"+opc+"\x20")
    get_empty_resp(ser)

def identify_regs(ser):
    val = randint(0, 255)
    print "A <= %x" % val
    write_reg(ser, 0xF0, val)
    dump_regs(ser)
    # Helper to identify registers
    exec_opcodes(ser, "\x38\x44\x30") # ADD SP, 44
    exec_opcodes(ser, "\x01\x01\x30") # ADD A, A
    exec_opcodes(ser, "\x5C\x40\x30") # MOX X, A 
    exec_opcodes(ser, "\x7D\x70\x30") # JMP 0x7030
    print "-----"
    dump_regs(ser)
    exit(0)

# get in sync with the AVR
print "syncing"
ser.write('\x30') # STK_GET_SYNC
ser.write('\x20') # STK_CRC_EOP

# receive sync ack
print "receiving sync ack"
get_empty_resp(ser)

time.sleep(0.1)
print 'Entering prog mode'
ser.write("\x50")
res = ser.read(1)
if res != "\x10":
    print "failed"
    exit(1)
    
time.sleep(0.1)
print 'Reading Signature'
ser.write("\x75\x20")
sig = get_n_resp(ser, 2)

print "Sig : %02X %02X" % (ord(sig[0]), ord(sig[1]))
    
print "setAddress(0)"
for addr in range(0, 64, 64):
    ser.write("\x55"+struct.pack(">H", addr)+"\x20")
    get_empty_resp(ser)
    res =  read_ram(ser,0xF8)
    print "%04X: %02x" % (addr, ord(res[0]))
dump_ram(ser)
exit(0)

# Read Addr 0 with ROMX
data = []
for i in range(0, 8192):
    sys.stdout.flush()
    write_reg(ser, 0xF0, i>>8) # A = 0
    write_reg(ser, 0xF3, i&0xFF) # X = 0
    exec_opcodes(ser, "\x28\x30\x40") # ROMX
    byte = read_reg(ser, 0xF0)
    print "%02x" % ord(byte[0]),
    data.append(byte)
print "\n"
print repr(data)
with open('flash', 'wb+') as out:
    out.write("".join(data))
exit(0)


#identify_regs(ser)

time.sleep(0.1)
print "read page (0x74)"
# Read 0x01 * 256 + 0x00 bytes
# F == flash
ser.write("\x74\x01\x00F\x20")
res = ser.read(1)
if res == "\x11":
    print "failed"
    exit(1)
data = []
try:
    while True:
        data.append(ser.read(256))
except KeyboardInterrupt:
    pass

with open('dump', 'wb+') as out:
    out.write("".join(data))
