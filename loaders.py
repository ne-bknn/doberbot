import subprocess
import json
from collections import defaultdict, MutableSequence
import pandas as pd
import logging

from typing import Tuple

logging.basicConfig(level=logging.WARNING)

class HTTPPacket:
    def __init__(self, http, tcp_seq, ip_src, ip_dst, tcp_data):
        self.sessionized = False
        new_http = defaultdict(str)
        for k, v in http.items():
            new_http[k] = v

        http = new_http
        self.tcp_seq = tcp_seq
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.tcp_data = bytes.fromhex(tcp_data.replace(":", "")).decode()
        self.http = {}
        if "http.request" in http.keys():
            self.http["type"] = "REQ"
            for k in http.keys():
                if isinstance(http[k], dict):
                    if "_ws.expert" in http[k].keys():
                        self.http["method"] = http[k]["http.request.method"]
                        self.http["uri"] = http[k]["http.request.uri"]
                        self.http["version"] = http[k]["http.request.version"]
                        break

            self.http["host"] = http["http.host"]
            self.http["ua"] = http["http.user_agent"]
            self.http["accept_enc"] = http["http.accept_encoding"]
            self.http["payload_length"] = http["http.content_length_header"]
            self.http["data"] = http["http.file_data"]

        elif "http.response" in http.keys():
            self.http["type"] = "RESP"
            for k in http.keys():
                if isinstance(http[k], dict):
                    if "_ws.expert" in http[k].keys():
                        self.http["version"] = http[k]["http.response.version"]
                        self.http["code"] = http[k]["http.response.code"]
                        break

            self.http["header_length"] = http["http.content_length_header"]
            self.http["server"] = http["http.server"]
            self.http["data"] = http["http.file_data"]
        else:
            raise ValueError("Could not determine packet type!")

    def __str__(self):
        return f"<HTTP TCPSQ:{self.tcp_seq} {self.http['type']}>"


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
                    sessions.append("[" + ", ".join([str(p) for p in session]) + "]")
                return (
                    "PacketList["
                    + ", ".join([str(session) for session in sessions])
                    + "]"
                )
        else:
            return "[]"

    def sessionize(self):
        self.sessionized = True
        temp_sessions = defaultdict(list)
        for packet in self._inner_list:
            temp_sessions[packet.tcp_seq].append(packet)

        sessions = list(temp_sessions.values())
        self._inner_list = sessions

    def to_pandas(self) -> Tuple[pd.DataFrame, list]:
        if not self.sessionized:
            raise ValueError(
                "PacketList must be sessionized before conversion to pandas!"
            )
        convlist = []
        texts = []
        for session in self._inner_list:
            tempdict = {}
            templist = []
            for packet in session:
                templist.append(packet.tcp_data)
                if packet.http["type"] == "REQ":
                    for k, v in packet.http.items():
                        if k == "type":
                            continue
                        tempdict[f"req_{k}"] = v
                elif packet.http["type"] == "RESP":
                    for k, v in packet.http.items():
                        if k == "type":
                            continue
                        tempdict[f"resp_{k}"] = v
                else:
                    raise ValueError("Invalid packet type!")
            convlist.append(tempdict)
            texts.append(templist)

        df = pd.DataFrame(convlist)
        return df, texts


class PcapLoader:
    """ Loader that uses pcap files """

    def __init__(self, filename):
        pcap = subprocess.run(
            ["tshark", "-r", filename, "-Y", "http", "-T", "json"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout
        pcap = json.loads(pcap.decode())
        self.packets = PacketList()
        for packet in pcap:
            tcp_seq = int(packet["_source"]["layers"]["tcp"]["tcp.stream"])
            ip_dst = packet["_source"]["layers"]["ip"]["ip.dst"]
            ip_src = packet["_source"]["layers"]["ip"]["ip.src"]
            http = packet["_source"]["layers"]["http"]
            try:
                tcp_data = packet["_source"]["layers"]["tcp.segments"]["tcp.reassembled.data"]
                logging.debug("Found reassembled.data")
            except KeyError:
                logging.debug("Could not find reassembled data, defaulting to tcp.payload")
                logging.debug(f"Available tcp fields: {packet['_source']['layers']['tcp'].keys()}")
                tcp_data = packet["_source"]["layers"]["tcp"]["tcp.payload"]

            new_packet = HTTPPacket(http, tcp_seq, ip_src, ip_dst, tcp_data)
            self.packets.append(new_packet)

        self.packets.sessionize()

    def get_conversations(self):
        return self.packets
