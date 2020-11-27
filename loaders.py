import subprocess
import json
from collections import defaultdict, MutableSequence


class HTTPPacket():
    def __init__(self, http, tcp_seq, ip_src, ip_dst):
        self.http = http
        self.tcp_seq = tcp_seq
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        if 'http.request' in self.http.keys():
            self.type = 'REQ'
        if 'http.response' in self.http.keys():
            self.type = 'RESP'

    def __str__(self):
        return f"<HTTP TCPSQ:{self.tcp_seq} {self.type}>"


class PacketList(MutableSequence):
    def __init__(self, initial=None):
        if initial is None:
            self._inner_list = list()
        else:
            self._inner_list = list(initial)

    def __len__(self):
        return len(self._inner_list)

    def __delitem__(self, index):
        self._innder_list.__delitem__(index)

    def insert(self, index, value):
        self._inner_list.insert(index, value)

    def __setitem__(self, index, value):
        self._inner_list.__setitem__(index, value)

    def __getitem__(self, index):
        return self._inner_list.__getitem__(index)

    def __str__(self):
        if len(self._inner_list) > 0:
            if isinstance(self._inner_list[0], list):
                sessions = []
                for session in self._inner_list:
                    sessions.append('['+", ".join([str(p) for p in session])+']')
                return 'PacketList['+", ".join([str(session) for session in sessions])+']'
        else:
            return '[]'

    def sessionize(self):
        temp_sessions = defaultdict(list)
        for packet in self._inner_list:
            temp_sessions[packet.tcp_seq].append(packet)

        sessions = list(temp_sessions.values())
        self._inner_list = sessions


class PcapLoader():
    """ Loader that uses pcap files """
    def __init__(self, filename):
        pcap = subprocess.run(["tshark", "-r", filename, "-Y", "http", "-T", "json"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
        pcap = json.loads(pcap.decode())
        self.packets = PacketList()
        for packet in pcap:
            tcp_seq = int(packet['_source']['layers']['tcp']['tcp.stream'])
            ip_dst = packet['_source']['layers']['ip']['ip.dst']
            ip_src = packet['_source']['layers']['ip']['ip.src']
            http = packet['_source']['layers']['http']
            new_packet = HTTPPacket(http, tcp_seq, ip_src, ip_dst)
            self.packets.append(new_packet)

        self.packets.sessionize()

    def get_conversations(self):
        return self.packets
