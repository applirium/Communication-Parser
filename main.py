from scapy.all import rdpcap
from binascii import hexlify
import yaml


class LiteralStr(str):
    pass


def database():
    with open("schemas/const.yaml", "r") as file:
        return yaml.safe_load(file)


def hex_convert(frame):
    index = 0
    result = ""
    for i in range(len(frame)):
        if index % 16 == 0 and index != 0:
            result += "\n"

        index += 1
        result += str(hexlify(frame[i:i + 1]))[2:-1].upper()
        if index % 16 != 0 and len(frame) != i + 1:
            result += " "
    return result + "\n"


def print_from_constatnts(specification, number, packet, packet_nameholder):
    try:
        packet[packet_nameholder] = constants[specification][number]
    except KeyError:
        pass


def print_adress(start, number, index, frame, separator, nominator=16):
    if nominator == 16:
        result = ""
        for i in range(index):
            result += print_sequence(start + i, number, frame) + separator
        return result[:-1]
    elif nominator == 10:
        result = ""
        for i in range(index):
            result += str(int(print_sequence(start + i, number, frame), 16)) + separator
        return result[:-1]


def print_sequence(start, number, frame):
    return str(hexlify(frame[start: start + number]))[2:-1].upper()


def print_mac(packet, raw_frame, offset=0):
    packet['src_mac'] = print_adress(6 + offset, 1, 6, raw_frame, ":")
    packet['dst_mac'] = print_adress(0 + offset, 1, 6, raw_frame, ":")


def print_ip(packet, raw_frame, start, end,code):
    src = print_adress(start, 1, 4, raw_frame, ".", 10)
    packet['src_ip'] = src
    packet['dst_ip'] = print_adress(end, 1, 4, raw_frame, ".", 10)

    if code == "IPv4":
        for node in list_of_senders:
            if node['node'] == src:
                node['number_of_sent_packets'] += 1
                return
        list_of_senders.append(node_creation(src))


def node_creation(ip):
    sender = {'node': ip, 'number_of_sent_packets': 1}
    return sender


def print_ports_protocols(packet, raw_frame, start, end):
    src = int(print_sequence(start, 2, raw_frame), 16)
    dst = int(print_sequence(end, 2, raw_frame), 16)
    packet['src_port'] = src
    packet['dst_port'] = dst
    print_from_constatnts("tcp_ports", min(src, dst), packet, 'app_protocol')


def uloha1_3(frames):
    data['name'] = "PKS2023/24"
    data['pcap_name'] = inp + ".pcap"
    data['packets'] = list_of_packets
    data['ipv4_senders'] = list_of_senders
    data['max_send_packets_by'] = max_send_packets
    index = 1

    for frame in frames:
        packet = {}

        raw_frame = bytes(frame)
        packet['frame_number'] = index
        packet['len_frame_pcap'] = len(frame)

        if len(frame) < 60:
            medium = 64
        else:
            medium = len(frame) + 4

        packet['len_frame_medium'] = medium
        ether_type = int(print_sequence(12, 2, raw_frame), 16)
        print_sequence(12, 2, raw_frame)
        if ether_type > 1500:
            packet['frame_type'] = "ETHERNET II"
            print_mac(packet, raw_frame)
            print_from_constatnts("ether_types", ether_type, packet ,'ether_type')
            if ether_type == 2048:
                ihl = 0
                if int(print_sequence(14, 1, raw_frame)) % 10 != 5:
                    ihl = 40
                print_ip(packet, raw_frame, 26, 30, "IPv4")
                print_from_constatnts("ip_protocols", int(print_sequence(23, 1, raw_frame), 16), packet, 'protocol')
                protocol = int(print_sequence(23, 1, raw_frame), 16)
                if protocol == 1:
                    print_from_constatnts("icmp_codes", int(print_sequence(34, 1, raw_frame), 16), packet, 'icmp_type')
                elif protocol == 6 or protocol == 17:
                    print_ports_protocols(packet, raw_frame, 34 + ihl, 36 + ihl)

            elif ether_type == 2054:
                operation = "INVALID"
                if int(print_sequence(20, 2, raw_frame), 16) == 1:
                    operation = "REQUEST"
                if int(print_sequence(20, 2, raw_frame), 16) == 2:
                    operation = "REPLY"
                packet['arp_opcode'] = operation
                print_ip(packet, raw_frame, 28, 38, "ARP")
        else:
            offset = 0
            if print_sequence(14, 2, raw_frame) == "FFFF":
                packet['frame_type'] = "IEEE 802.3 RAW"
                print_mac(packet, raw_frame)

            elif print_sequence(14, 1, raw_frame) == "AA" or print_sequence(0, 4, raw_frame) == "01000c00":
                if print_sequence(40, 1, raw_frame) == "AA":
                    offset = 26
                packet['frame_type'] = "IEEE 802.3 LLC & SNAP"
                print_mac(packet, raw_frame, offset)
                print_from_constatnts("ether_types", int(print_sequence(20 + offset, 2, raw_frame), 16), packet, 'PID')

            else:
                packet['frame_type'] = "IEEE 802.3 LLC"
                print_mac(packet, raw_frame)
                print_from_constatnts("saps", int(print_sequence(15, 1, raw_frame), 16), packet, 'SAP')
        packet['hexa_frame'] = LiteralStr(hex_convert(raw_frame))

        list_of_packets.append(packet)
        index += 1

    max = 0
    for node in list_of_senders:
        if node['number_of_sent_packets'] > max:
            max = node['number_of_sent_packets']

    for node in list_of_senders:
        if node['number_of_sent_packets'] == max:
            max_send_packets.append(node['node'])


def yaml_create(data):
    def change_style(style, representer):
        def new_representer(dumper, data):
            scalar = representer(dumper, data)
            scalar.style = style
            return scalar
        return new_representer

    represent_literal_str = change_style('|', yaml.representer.SafeRepresenter.represent_str)
    yaml.add_representer(LiteralStr, represent_literal_str)

    with open("output/result.yaml", "w") as file:
        yaml.dump(data, file, sort_keys=False)


data = {}
communication = {}

list_of_packets = []
list_of_senders = []
max_send_packets = []

list_of_communications = []

constants = database()
temp = True
while temp:
    #inp = input("Zadaj pcap na rozbor: ")
    inp = "eth-1"
    try:
        #frames = rdpcap("pcap/" + inp + ".pcap")
        frames = rdpcap("pcap/eth-1.pcap")
        temp = False
    except FileNotFoundError:
        continue

    uloha1_3(frames)
    yaml_create(data)
