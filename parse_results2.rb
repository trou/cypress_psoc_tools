#!/usr/bin/env ruby

require "pp"

data = File.open(ARGV.shift, "rt").readlines
last_csum = 0x80
last_delay = 24
bytes = [[0x80, 0x80]]
data.each do |line|
    m = line.match(/(?<delay>[0-9]+) (?<f1>[0-9A-F]{2}) (?<lsb>[0-9A-F]{2}) (?<msb>[0-9A-F]{2})/)
    if not m then
        next
    end
    # noise
    next if m[:f1] != "FB" && m[:f1] != "CC"
    csum = m[:lsb].to_i(16)| (m[:msb].to_i(16)<<8)
    delay = m[:delay].to_i
    if (csum != last_csum and delay-last_delay > 14) or (delay-last_delay > 30) then
        # check problems with carry
        if csum-last_csum == 0x100 then
            next
        else
            bytes << [((csum-last_csum)&0xFF), csum]
        end
        puts "%d %04X (old: %04X, val: %02X)" % [delay, csum, last_csum, bytes[-1][0]]
        last_delay = delay
        last_csum = csum
    end
end

puts bytes.map{|p| p[0]}.pack('C*').unpack('H*')
if ARGV[0] then
    out = File.open(ARGV[0], "wb+")
    out.write( bytes.map{|p| p[0]}.pack('C*'))
end
