#!/usr/bin/env python

import time
import serial
ser = serial.Serial('/dev/ttyACM0', 57600, timeout=1)  # open serial port


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

def dump_ram(ser):
    ram = []
    for i in range(0, 256):
        data = read_ram(ser, i)
        ram.append(data)

    with open('dump', 'wb+') as out:
        out.write("".join(ram))

def exec_opcodes(ser, opc):
    ser.write("\x83"+opc+"\x20")
    get_empty_resp(ser)

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
res = ser.read(1)
if res == "\x11":
    print "failed"
    exit(1)

sig = ser.read(2)
ok = ser.read(1)

print "Sig : %02X %02X" % (ord(sig[0]), ord(sig[1]))
    
time.sleep(0.3)
print "setAddress(0)"
ser.write("\x55\x00\x00\x20")

get_empty_resp(ser)

print "read F6"
ser.write("\x79\xF4\x20")
data = get_byte_resp(ser)
print repr(data)

print "read KEY1"
ser.write("\x81\xF8\x20")
data = get_byte_resp(ser)
if data == "\x01":
    print "address is protected !"
    exit(0)

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
