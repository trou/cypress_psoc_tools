#!/usr/bin/env python

import struct
import sys
import time
from random import randint
import serial

class SyncFailed(Exception):
    pass

def print_nocr(s):
    print s,
    sys.stdout.flush()

def hexdump(src, length=16, sep='.'):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        if len(hex) > 24:
            hex = "%s %s" % (hex[:24], hex[24:])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
        lines.append("%08x:  %-*s  |%s|\n" % (c, length*3, hex, printable))
    print ''.join(lines)

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
        raise SyncFailed("%s, %s"% (repr(insync), repr(ok)))

def sync_arduino():
    print_nocr("syncing: ")
    while True:
        try:
            # get in sync with the AVR
            ser.write('\x30\x20') # STK_GET_SYNC
            get_empty_resp()
        except SyncFailed:
            print_nocr("KO ")
            pass
        else:
            print "OK"
            break

def reset_psoc(quiet=False):
    while True:
        if not quiet:
            print_nocr('Resetting PSoC: ')
        ser.write("\x49")
        res = ser.read(1)
        if res != "\x10":
            if not quiet:
                print_nocr("KO ")
            continue
        else:
            if not quiet:
                print "OK"
            return

def send_vectors():
    ser.write("\x50")
    res = get_byte_resp()
    if res != "\x00":
        raise RuntimeError("init failed")

def write_reg(reg, value):
    ser.write("\x80"+chr(reg)+chr(value)+"\x20")
    get_empty_resp()

def read_reg(reg):
    ser.write("\x79"+chr(reg)+"\x20")
    return get_byte_resp()

def read_regb(reg):
    return ord(read_reg(reg)[0])

def read_ram(addr):
    ser.write("\x81"+chr(addr)+"\x20")
    return get_byte_resp()

def read_ramb(addr):
    return ord(read_ram(addr)[0])


def write_ram(addr, value):
    ser.write("\x82"+chr(addr)+chr(value)+"\x20")
    get_empty_resp()

def dump_regs():
    for reg in range(0xF0, 0xFF):
        print "%2s [%02X] %02X " % (REGS[reg], reg, ord(read_reg(reg)[0]))

def switch_ram_page(pg):
    if pg == 1:
        write_reg(0xF7, 0)
        write_reg(0xD0, 0x1) # Set CUR_PP to 1
        write_reg(0xD3, 0x1) # Set IDX_PP to 1
        write_reg(0xD4, 0x1) # Set MVR_PP to 1
        write_reg(0xF7, 0x80) # Set PgMode to CUR_PP / IDX_PP
    else:
        write_reg(0xF7, 0)

def dump_ram(fname):
    # Dump page 0
    write_reg(0xF7, 0) # Set CPU_F to 0, so that page 0 is accessed
    ram = []
    for i in range(0, 256):
        data = read_ram(i)
        ram.append(data)
    switch_ram_page(1)
    for i in range(0, 256):
        data = read_ram(i)
        ram.append(data)

    if fname is not None:
        with open(fname, 'wb+') as out:
            out.write("".join(ram))
    else:
        hexdump(ram)

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
def read_0x80_data(length):
    print "read page (0x74)"
    # Read 0x00 * 256 + 0x60 bytes
    # F == flash
    ser.write("\x74"+struct.pack('>H', length)+"\x20")
    res = ser.read(1)
    if res == "\x11":
        print "failed"
        exit(1)
    data = []
    for i in range(0, length):
        data.append(ser.read(256))
    return data

def read_security_data():
    ser.write("\x86")
    if get_byte_resp() != "\x00":
        print "Reading security data failed"
        exit(1)

    data = []
    for i in range(0x80, 0x80+32):
        data.append(read_ramb(i))
    sec_data = {0: 'unprotected', 1: 'read protect', 2: 'Disable external write', 3: 'Disable internal write'}
    for i in range(0, 128):
        print "block %02x : %s" % (i, sec_data[data[i*2/8]>>(6-(i%4)*2)&3])


def cold_boot_step():
    print "Trying checksum & reset"
    # Try to checksum
    for delay in range(500, 5000, 2000):
        ser.write("\x85"+struct.pack(">H", delay))
        res = ser.read(1)
        print "%d: %02X %02X" % (delay, read_ramb(0xF8), read_ramb(0xF9))
        dump_ram("ram_csum_%05d" % delay)
    exit(0)

# get in sync with the AVR
print "syncing"
ser.write('\x30\x20') # STK_GET_SYNC

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

cold_boot_step()
#dump_ram("fullram_startup")
#read_security_data()

exit(0)
