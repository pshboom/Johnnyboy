
#-*- coding: utf-8 -*-
#2번줄을 입력해야만 코드 내에 한글이 있어도 사용이 가능하다.
import struct
import socket
class Packet:

    def __init__(self):
        pass

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
        self.dstination_mac = data[offset: offset + 6].encode("hex")
        offset += 6
        self.source_mac = data[offset: offset + 6].encode("hex")
        offset += 6
        self.ethernet_type = data[offset:offset + 2].encode("hex")
        offset += 2
        self.IP = None
        Ethernet_result = ('Source Mac : '+self.source_mac+', Destination Mac : '+self.dstination_mac+', Ethernet Type : '+self.ethernet_type+'\n')
        print Ethernet_result
        f.write(Ethernet_result)
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
        IP_result = ('Source IP : '+self.source_ip+', Destination IP : '+self.destination_ip+', Protocol : '+str(self.protocol)+'\n')
        print IP_result
        f.write(IP_result)
        if self.protocol == 6:
            self.TCP = TCP()
            self.TCP.analysis(data, offset, packet_ends_offset)
        elif self.protocol == 17:
            self.UDP = UDP()
            self.UDP.analysis(data, offset, packet_ends_offset)


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
        TCP_results = ('TCP, Source Port : '+str(self.source_port)+', Destination Port : '+str(self.destination_port)+', Flags : '+self.flags+'\n')
        print TCP_results
        f.write(TCP_results)
        if self.source_port == 80 and self.flags.find("P")>-1:
            TCP_payload = self.payload.split("\r\n")
            print TCP_payload
            f.write('\n'.join(TCP_payload))
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

    def analysis(self, data, offset, packet_ends_offset):
        self.source_port = struct.unpack(">H", data[offset: offset + 2])[0]
        offset += 2
        self.destination_port = struct.unpack(">H", data[offset: offset + 2])[0]
        offset += 2
        self.header_length = struct.unpack("<H", data[offset: offset + 2])[0]
        offset += 2
        self.checksum = struct.unpack("<H", data[offset: offset + 2])[0]
        offset += 2
        self.payload = data[offset: packet_ends_offset].split('\r\n')
        UDP_results = ('UDP, Source Port : '+str(self.source_port)+', Destination Port : '+str(self.destination_port)+', Header Length : '+str(self.header_length)+'\n')
        print UDP_results
        f.write(UDP_results)
        #raw_input()



class PcapHeader:
    def __init__(self):
        pass

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
fd = open("test3.pcap", "rb") # 파일을 불러옴
data = fd.read() # data에 파일 내용을을 집어넣어 메모리에 올림
fd.close() # 파일사용을 종료함
pcapHeader = PcapHeader() # pcapheader 클래스 선언
offset = 0 # offset 초기화
offset = pcapHeader.analysis(data, offset) #pcapheader의 analysis 메소드 호출
index = 1
f = open("result.txt", 'w')
while True:
    if offset >= len(data):
        break
    print(index)
    f.write(str(index))
    f.write('\n')
    packet = Packet()
    offset = packet.packet_header(data, offset)
    packet.analysis(data[offset: offset + packet.incl_len], offset + packet.incl_len)
    offset = offset + packet.incl_len
    packets.append(packet)
    index += 1


f.close()
