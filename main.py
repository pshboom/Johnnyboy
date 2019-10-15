import struct
import socket
class Packet:

    def __init__(self):
        '''pass'''

    def packet_header(self, data, offset):
        self.ts_sec = struct.unpack('<L', data[offset: offset + 4])[0]
        offset += 4
        self.ts_usec = struct.unpack('<L', data[offset: offset + 4])[0]
        offset += 4
        self.incl_len = struct.unpack('<L', data[offset: offset + 4])[0]
        offset += 4
        self.orig_len = struct.unpack('<L', data[offset: offset + 4])[0]
        offset += 4
        return offset

    def analysis(self, data, packet_ends_offset):
        self.data_length = len(data)
        ethernet = Ethernet()
        ethernet.analysis(data, packet_ends_offset)


class Ethernet:

    def analysis(self, data, packet_ends_offset):
        offset = 0
        self.dstination_mac = data[offset: offset + 6]#.encode("hex")
        offset += 6
        self.source_mac = data[offset: offset + 6]#.encode("hex")
        offset += 6
        self.ethernet_type = data[offset:offset + 2]#.encode("hex")
        offset += 2
        self.IP = None
        print (self.source_mac, self.dstination_mac, self.ethernet_type)
        if self.ethernet_type == "0800":
            self.IP = IP()
            self.IP.analysis(data, offset, packet_ends_offset)


class IP:

    def analysis(self, data, offset, packet_ends_offset):
        offset += 8
        self.ttl = struct.unpack("<B", data[offset])[0]
        offset += 1
        self.protocol = struct.unpack("<B", data[offset])[0]
        offset += 1
        self.checksum = None
        offset += 2
        self.source_ip = socket.inet_ntoa(data[offset:offset + 4])
        offset += 4
        self.destination_ip = socket.inet_ntoa(data[offset:offset + 4])
        offset += 4
        print(self.source_ip, self.destination_ip, self.ttl)
        if self.protocol == 6:
            self.TCP = TCP()
            self.TCP.analysis(data, offset, packet_ends_offset)


class TCP:

    def analysis(self, data, offset, packet_ends_offset):
        self.source_port = struct.unpack(">H", data[offset: offset + 2])[0]
        offset += 2
        self.destination_port = struct.unpack(">H", data[offset: offset + 2])[0]
        offset += 2
        self.seq_number = struct.unpack("<L", data[offset: offset + 4])[0]
        offset += 4
        self.ack_number = struct.unpack("<L", data[offset: offset + 4])[0]
        offset += 4
        self.header_length = struct.unpack("<B", data[offset: offset + 1])[0]
        self.flags = self.getFlags(data=data[offset: offset + 2])
        offset += 2
        self.window_size = struct.unpack("<H", data[offset: offset + 2])[0]
        offset += 2
        self.checksum = struct.unpack("<H", data[offset: offset + 2])[0]
        offset += 2
        self.urgent_pointer = data[offset: offset + 2]
        offset += 2
        self.payload = data[offset: packet_ends_offset]
        print
        self.source_port, self.destination_port, self.flags, len(self.payload)
        #raw_input()

    def getFlags(self, data):
        flags = ''
        second_byte = bin(ord(data[1]))[2:]
        second_byte = (8 - len(second_byte)) * "0" + second_byte
        if second_byte[2] == "1":
            flags += "U"
        if second_byte[4] == "1":
            flags += "P"
        if second_byte[5] == "1":
            flags += "R"
        if second_byte[6] == "1":
            flags += "S"
        if second_byte[7] == "1":
            flags += "F"
        if second_byte[3] == "1":
            flags += "A"
        return flags


class UDP:

    def __init__(self, data):
        pass


class PcapHeader:
    def __init__(self):
        '''pass'''

    def analysis(self, data, offset):
        self.magic_number = data[offset: offset + 4]
        offset += 4
        self.verion_major = struct.unpack('<H', data[offset: offset + 2])[0]
        offset += 2
        self.version_minor = struct.unpack('<H', data[offset: offset + 2])[0]
        offset += 2
        self.thiszone = struct.unpack('<L', data[offset: offset + 4])[0]
        offset += 4
        self.sigfigs = struct.unpack('<L', data[offset: offset + 4])[0]
        offset += 4
        self.snaplen = struct.unpack('<L', data[offset: offset + 4])[0]
        offset += 4
        self.network = struct.unpack('<L', data[offset: offset + 4])[0]
        offset += 4
        return offset


packets = [] # 패킷 선언
fd = open("test.pcap", "rb") # 파일을 불러옴
data = fd.read() # data에 파일 내용을을 집어넣어 메모리에 올림
fd.close() # 파일사용을 종료함
pcapHeader = PcapHeader() # pcapheader 클래스 선언
offset = 0 # offset 초기화
offset = pcapHeader.analysis(data, offset) #pcapheader의 analysis 메소드 호출
index = 1

while True:
    if offset >= len(data):
        break
    print(index)
    packet = Packet()
    offset = packet.packet_header(data, offset)
    packet.analysis(data[offset: offset + packet.incl_len], offset + packet.incl_len)
    offset = offset + packet.incl_len
    packets.append(packet)
    index += 1
