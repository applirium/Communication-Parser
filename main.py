from scapy.all import rdpcap
from binascii import hexlify
import yaml


class LiteralStr(str):
    pass


class Protocol:
    def __init__(self, num, src_ip, dst_ip):
        self.num = num
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.packets = []

    def packet_add(self, packet):
        self.packets.append(packet)


class TCP(Protocol):
    def __init__(self, num, src_ip, dst_ip, src_port, dst_port):
        super().__init__(num, src_ip, dst_ip)
        self.src_port = src_port
        self.dst_port = dst_port
        self.start = [0, False]
        self.end = [0, False]


class TFTP(Protocol):
    def __init__(self, num, src_ip, dst_ip, client_port):
        super().__init__(num, src_ip, dst_ip)
        self.client_port = client_port


class ICMP(Protocol):
    def __init__(self, num, src_ip, dst_ip, icmp_id, icmp_seq):
        super().__init__(num, src_ip, dst_ip)
        self.icmp_id = icmp_id
        self.icmp_seq = icmp_seq


def database():
    with open("schemas/const.yaml", "r") as file:
        return yaml.safe_load(file)


def dict_search(dic, string):
    for key, value in dic.items():
        if value == string:
            return key


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


def print_ip(packet, raw_frame, start, end, code):
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


def packet_analyze(frame, index, extended=False, frag=False):
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
        print_from_constatnts("ether_types", ether_type, packet, 'ether_type')
        if ether_type == 2048:
            ihl = (int(print_sequence(14, 1, raw_frame)[-1], 16) * 4) - 20

            print_ip(packet, raw_frame, 26, 30, "IPv4")

            if (int(print_sequence(16, 2, raw_frame), 16) == 1500 or frag) and extended:
                binary = int(format(int(print_sequence(20, 2, raw_frame), 16), '16b'))
                frag = bool(binary // 10000000000000)

                packet['id'] = int(print_sequence(18, 2, raw_frame), 16)
                packet['flags_mf'] = frag
                packet['frag_offset'] = int(str(binary % 10000000000000), 2) * 8

            print_from_constatnts("ip_protocols", int(print_sequence(23, 1, raw_frame), 16), packet, 'protocol')
            protocol = int(print_sequence(23, 1, raw_frame), 16)

            if protocol == 1:
                print_from_constatnts("icmp_codes", int(print_sequence(34 + ihl, 1, raw_frame), 16), packet,
                                      'icmp_type')
                if extended:
                    packet['icmp_id'] = int(print_sequence(38 + ihl, 2, raw_frame), 16)
                    packet['icmp_seq'] = int(print_sequence(40 + ihl, 2, raw_frame), 16)
            else:
                src = int(print_sequence(34 + ihl, 2, raw_frame), 16)
                dst = int(print_sequence(36 + ihl, 2, raw_frame), 16)
                packet['src_port'] = src
                packet['dst_port'] = dst

                if protocol == 6:
                    flag = int(print_sequence(47 + ihl, 1, raw_frame), 16)
                    if flag == 24 or flag == 25:
                        print_from_constatnts("tcp_ports", min(src, dst), packet, 'app_protocol')

                    if extended:
                        print_from_constatnts("flags", flag, packet, 'flag')

                elif protocol == 17:
                    print_from_constatnts("tcp_ports", min(src, dst), packet, 'app_protocol')

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
    return packet


def uloha1_all(frames):
    data['name'] = "PKS2023/24"
    data['pcap_name'] = inp + ".pcap"
    data['packets'] = list_of_packets
    data['ipv4_senders'] = list_of_senders
    data['max_send_packets_by'] = max_send_packets
    index = 1

    for frame in frames:
        list_of_packets.append(packet_analyze(frame, index))
        index += 1

    maximum = 0
    for node in list_of_senders:
        if node['number_of_sent_packets'] > maximum:
            maximum = node['number_of_sent_packets']

    for node in list_of_senders:
        if node['number_of_sent_packets'] == maximum:
            max_send_packets.append(node['node'])


def tcp_deletion(comm, reading_comms):
    dict_comm = {'number_comm': comm.num, 'src_comm': comm.src_ip, 'dst_comm': comm.dst_ip, 'packets': comm.packets}
    if comm.start[1] and comm.end[1]:
        list_of_complete_comms.append(dict_comm)
    else:
        list_of_partial_comms.append(dict_comm)
    reading_comms.remove(comm)


def udp_deletion(comm, reading_comms):
    dict_comm = {'number_comm': comm.num, 'src_comm': comm.src_ip, 'dst_comm': comm.dst_ip, 'packets': comm.packets}
    if (comm.packets[-2]['len_frame_pcap'] < comm.packets[1]['len_frame_pcap'] and
            comm.packets[-1]['len_frame_pcap'] == 60):
        list_of_complete_comms.append(dict_comm)
    else:
        list_of_partial_comms.append(dict_comm)
    reading_comms.remove(comm)


def icmp_deletion(comm, reading_comms):
    dict_comm = {'number_comm': comm.num, 'src_comm': comm.src_ip, 'dst_comm': comm.dst_ip, 'packets': comm.packets}
    openning = 0
    ending = 0
    for packet in comm.packets:
        flag = packet['icmp_type']
        if flag == "Echo Request":
            openning += 1
        elif flag == "Echo Reply" or flag == "Time Exceeded":
            ending += 1

        if packet['icmp_id'] == 0 and packet['icmp_seq'] == 0:
            packet.pop('icmp_id')
            packet.pop('icmp_seq')

        try:
            if packet['flags_mf']:
                packet.pop('protocol')
                packet.pop('icmp_type')
                packet.pop('icmp_id')
                packet.pop('icmp_seq')
        except KeyError:
            continue

    if openning == ending and openning != 0 and ending != 0:
        list_of_complete_comms.append(dict_comm)
    else:
        list_of_partial_comms.append(dict_comm)

    reading_comms.remove(comm)


def arp_deletion(comm, reading_comms):
    dict_comm = {'number_comm': comm.num, 'packets': comm.packets}
    request = 0
    reply = 0
    for packet in comm.packets:
        opcode = packet['arp_opcode']
        if opcode == "REQUEST":
            request += 1
        else:
            reply += 1

    if request != 0 and reply != 0 and comm.packets[-1]['arp_opcode'] == "REPLY":
        list_of_complete_comms.append(dict_comm)
    else:
        list_of_partial_comms.append(dict_comm)

    reading_comms.remove(comm)


def check(comm, packet):
    if (comm.src_ip == packet['src_ip'] and
            comm.dst_ip == packet['dst_ip'] and
            comm.src_port == packet['src_port'] and
            comm.dst_port == packet['dst_port']):
        return True
    else:
        return False


def check_reversed(comm, packet):
    if (comm.dst_ip == packet['src_ip'] and
            comm.src_ip == packet['dst_ip'] and
            comm.src_port == packet['dst_port'] and
            comm.dst_port == packet['src_port']):
        return True
    else:
        return False


def tcp_establishment(comm, check_one, check_two):
    pck = comm.packets[-1]
    if comm.start[0] == 0 and pck['flag'] == "SYN" and check_one(comm, pck):
        comm.start[0] = 1
        return True
    elif comm.start[0] == 1 and pck['flag'] == "SYN-ACK" and check_two(comm, pck):
        comm.start[0] = 21
        return True
    elif comm.start[0] == 1 and pck['flag'] == "SYN" and check_two(comm, pck):
        comm.start[0] = 22
        return True
    elif comm.start[0] == 22 and pck['flag'] == "ACK" and check_one(comm, pck):
        comm.start[0] = 32
        return True
    elif comm.start[0] == 21 and pck['flag'] == "ACK" and check_one(comm, pck):
        comm.start[1] = True
        return True
    elif comm.start[0] == 32 and pck['flag'] == "ACK" and check_two(comm, pck):
        comm.start[1] = True
        return True
    return False


def tcp_termination(comm, check_one, check_two):
    pck = comm.packets[-1]
    if comm.end[0] == 0 and (pck['flag'] == "FIN-ACK" or pck['flag'] == "FIN-PUSH-ACK") and check_one(comm, pck):
        comm.end[0] = 1
        return True
    elif comm.end[0] == 1 and pck['flag'] == "ACK" and check_two(comm, pck):
        comm.end[0] = 21
        return True
    elif comm.end[0] == 1 and (pck['flag'] == "FIN-ACK" or pck['flag'] == "FIN-PUSH-ACK") and check_two(comm, pck):
        comm.end[0] = 22
        return True
    elif comm.end[0] == 21 and (pck['flag'] == "FIN-ACK" or pck['flag'] == "FIN-PUSH-ACK") and check_two(comm, pck):
        comm.end[0] = 31
        return True
    elif comm.end[0] == 22 and pck['flag'] == "ACK" and check_one(comm, pck):
        comm.end[0] = 32
        return True
    elif ((comm.end[0] == 31 and pck['flag'] == "ACK" and check_one(comm, pck)) or
          (comm.end[0] == 32 and pck['flag'] == "ACK" and check_two(comm, pck)) or
          pck['flag'] == "RST" and check_two(comm, pck)):
        comm.end[1] = True
        return True
    return False


def uloha4_tcp(frames, protocol_port):
    data['name'] = "PKS2023/24"
    data['pcap_name'] = inp + ".pcap"
    print_from_constatnts("tcp_ports", protocol_port, data, 'filter_name')
    index = 1
    comms = 1

    cr_comms = []
    for frame in frames:
        packet = packet_analyze(frame, index, True)
        index += 1
        try:
            if packet['dst_port'] == protocol_port or packet['src_port'] == protocol_port:
                skip = False
                for comm in cr_comms:
                    if check(comm, packet) or check_reversed(comm, packet):
                        comm.packet_add(packet)

                        if comm.start[1] is False:
                            if not tcp_establishment(comm, check, check_reversed):
                                tcp_establishment(comm, check_reversed, check)

                        if comm.end[1] is False:
                            if not tcp_termination(comm, check, check_reversed):
                                tcp_termination(comm, check_reversed, check)

                        if comm.start[1] and comm.end[1]:
                            tcp_deletion(comm, cr_comms)
                        skip = True
                        break
                if skip:
                    continue

                tcp_object = TCP(comms, packet['src_ip'], packet['dst_ip'], packet['src_port'], packet['dst_port'])
                tcp_object.packet_add(packet)

                if tcp_object.start[0] == 0 and packet['flag'] == "SYN" and check(tcp_object, packet):
                    tcp_object.start[0] = 1

                cr_comms.append(tcp_object)
                comms += 1
        except KeyError:
            continue

    while len(cr_comms) != 0:
        tcp_deletion(cr_comms[0], cr_comms)

    if len(list_of_complete_comms) != 0:
        data['complete_comms'] = list_of_complete_comms
    if len(list_of_partial_comms) != 0:
        data['partial_comms'] = list_of_partial_comms


def uloha4_udp(frames, protocol_port):
    data['name'] = "PKS2023/24"
    data['pcap_name'] = inp + ".pcap"
    print_from_constatnts("tcp_ports", protocol_port, data, 'filter_name')
    index = 1
    comms = 1

    cr_comms = []
    for frame in frames:
        packet = packet_analyze(frame, index, True)
        index += 1
        try:
            if packet['dst_port'] == protocol_port:
                udp_object = TFTP(comms, packet['src_ip'], packet['dst_ip'], packet['src_port'])
                udp_object.packet_add(packet)
                cr_comms.append(udp_object)
                comms += 1
                continue

            for comm in cr_comms:
                if comm.client_port == packet['src_port'] or comm.client_port == packet['dst_port']:
                    hexa = packet['hexa_frame']
                    packet.pop('hexa_frame')

                    packet['app_protocol'] = "TFTP"
                    packet['hexa_frame'] = hexa
                    comm.packet_add(packet)
                    break

        except KeyError:
            continue

    while len(cr_comms) != 0:
        udp_deletion(cr_comms[0], cr_comms)

    if len(list_of_complete_comms) != 0:
        data['complete_comms'] = list_of_complete_comms
    if len(list_of_partial_comms) != 0:
        data['partial_comms'] = list_of_partial_comms


def uloha4_icmp(frames):
    data['name'] = "PKS2023/24"
    data['pcap_name'] = inp + ".pcap"
    index = 1
    comms = 1

    cr_comms = []
    frag = False
    for frame in frames:

        packet = packet_analyze(frame, index, True, frag)
        try:
            frag = packet['flags_mf']
        except KeyError:
            frag = False

        index += 1
        try:
            if packet['protocol'] == "ICMP":
                skip = False
                for comm in cr_comms:
                    try:
                        if comm.packets[-1]['flags_mf']:
                            hexa = packet['hexa_frame']
                            packet.pop('icmp_id')
                            packet.pop('icmp_seq')
                            packet.pop('hexa_frame')

                            packet['icmp_type'] = comm.packets[-1]['icmp_type']
                            packet['icmp_id'] = comm.packets[-1]['icmp_id']
                            packet['icmp_seq'] = comm.packets[-1]['icmp_seq']
                            packet['hexa_frame'] = hexa
                            comm.packet_add(packet)
                            skip = True
                            break
                    except KeyError:
                        pass

                    if (((comm.src_ip == packet['dst_ip'] and comm.dst_ip != packet['src_ip'] and
                          packet['icmp_type'] == "Time Exceeded" and comm.packets[-1]['icmp_type'] == "Echo Request") or
                         (comm.src_ip == packet['src_ip'] and comm.dst_ip == packet['dst_ip']) or
                         (comm.src_ip == packet['dst_ip'] and comm.dst_ip == packet['src_ip'])) and
                            (comm.icmp_id == packet['icmp_id'] or packet['icmp_id'] == 0) and
                            (packet['icmp_type'] == "Echo Request" or packet['icmp_type'] == "Time Exceeded" or packet[
                                'icmp_type'] == "Echo Reply")):
                        comm.packet_add(packet)
                        skip = True
                        break

                if skip:
                    continue

                icmp_object = ICMP(comms, packet['src_ip'], packet['dst_ip'], packet['icmp_id'], packet['icmp_seq'])
                icmp_object.packet_add(packet)
                cr_comms.append(icmp_object)
                comms += 1

        except KeyError:
            continue

    while len(cr_comms) != 0:
        icmp_deletion(cr_comms[0], cr_comms)

    if len(list_of_complete_comms) != 0:
        data['complete_comms'] = list_of_complete_comms
    if len(list_of_partial_comms) != 0:
        data['partial_comms'] = list_of_partial_comms


def uloha4_arp(frames):
    data['name'] = "PKS2023/24"
    data['pcap_name'] = inp + ".pcap"
    index = 1
    comms = 1

    cr_comms = []
    for frame in frames:
        packet = packet_analyze(frame, index, True)
        index += 1

        try:
            if packet['ether_type'] == "ARP":
                skip = False
                for comm in cr_comms:
                    if (comm.src_ip == packet['dst_ip'] and comm.dst_ip == packet['src_ip']) or (
                            comm.dst_ip == packet['dst_ip'] and comm.src_ip == packet['src_ip']):
                        comm.packet_add(packet)
                        skip = True
                        break
                if skip:
                    continue

                if packet['arp_opcode'] == "REQUEST":
                    arp_object = Protocol(comms, packet['src_ip'], packet['dst_ip'])
                else:
                    arp_object = Protocol(comms, packet['dst_ip'], packet['src_ip'])

                arp_object.packet_add(packet)
                cr_comms.append(arp_object)
                comms += 1

        except KeyError:
            continue

    while len(cr_comms) != 0:
        arp_deletion(cr_comms[0], cr_comms)

    if len(list_of_complete_comms) != 0:
        data['complete_comms'] = list_of_complete_comms
    if len(list_of_partial_comms) != 0:
        data['partial_comms'] = list_of_partial_comms


def yaml_create(obj, name):
    def change_style(style, representer):
        def new_representer(dumper, datas):
            scalar = representer(dumper, datas)
            scalar.style = style
            return scalar

        return new_representer

    represent_literal_str = change_style('|', yaml.representer.SafeRepresenter.represent_str)
    yaml.add_representer(LiteralStr, represent_literal_str)

    with open("output/" + name, "w") as file:
        yaml.dump(obj, file, sort_keys=False)


# TODO optimalizacia
# TODO bug finding


data = {}

list_of_packets = []
list_of_senders = []
max_send_packets = []

list_of_partial_comms = []
list_of_complete_comms = []

pcap = None
constants = database()

while True:
    # inp = input("Zadaj pcap na rozbor: ")
    inp = "trace_ip_nad_20_B"
    try:
        # pcap = rdpcap("pcap/" + inp + ".pcap")
        pcap = rdpcap("pcap/trace_ip_nad_20_B.pcap")
        break
    except FileNotFoundError:
        continue

print("ALL | HTTP | HTTPS | TELNET | FTP-CONTROL | FTP-DATA | TFTP | ICMP | ARP")
inp2 = input("Zadaj filter: ").upper()

if inp2 == "ALL":
    uloha1_all(pcap)
    yaml_create(data, "result-all.yaml")
elif inp2 == "HTTP" or inp2 == "HTTPS" or inp2 == "TELNET" or inp2 == "FTP-CONTROL" or inp2 == "FTP-DATA":
    uloha4_tcp(pcap, dict_search(constants['tcp_ports'], inp2))
    yaml_create(data, "result-" + inp2.lower() + ".yaml")
elif inp2 == "TFTP":
    uloha4_udp(pcap, dict_search(constants['tcp_ports'], inp2))
    yaml_create(data, "result-tftp.yaml")
elif inp2 == "ICMP":
    uloha4_icmp(pcap)
    yaml_create(data, "result-icmp.yaml")
elif inp2 == "ARP":
    uloha4_arp(pcap)
    yaml_create(data, "result-arp.yaml")
else:
    print("Invalid input")
