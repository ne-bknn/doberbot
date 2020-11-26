import scapy
import scapy.all as scapy_all
from scapy.layers import http

class AbstractLoader():
    """ Specification of Loader interface """
    def __init__(self):
        """ Class constructor should get all the data needed to
        pull the streams and create list of conversations
        """

    def __iter__(self):
        """ Should return a packet per iteration """

class PcapLoader(AbstractLoader):
    """ Loader that uses pcap files """
    def __init__(self, filename, port):
        """ For details about this solution see scapy_test.ipynb in research """
        scapy_all.bind_layers(scapy_all.TCP, http.HTTP, sport=port)
        scapy_all.bind_layers(scapy_all.TCP, http.HTTP, dport=port)

        pcap = scapy.utils.rdpcap(filename)

        sessions = pcap.sessions(self.full_duplex)

        self.conversations = []
        for session in sessions.keys():
            conversation = []
            for packet in sessions[session]:
                if http.HTTPRequest in packet:
                    conversation.append(packet.lastlayer())

                if http.HTTPResponse in packet:
                    conversation.append(packet.lastlayer())

            if len(conversation) != 0:
                self.conversations.append(conversation)

    def __len__(self):
        return len(self.conversations)

    @staticmethod
    def full_duplex(p):
        sess = "Other"
        if 'Ether' in p:
            if 'IP' in p:
                if 'TCP' in p:
                    sess = str(sorted(["TCP", p[scapy_all.IP].src, p[scapy_all.TCP].sport, p[scapy_all.IP].dst, p[scapy_all.TCP].dport], key=str))
                elif 'UDP' in p:
                    sess = str(sorted(["UDP", p[scapy_all.IP].src, p[scapy_all.UDP].sport, p[scapy_all.IP].dst, p[scapy_all.UDP].dport], key=str))
                elif 'ICMP' in p:
                    sess = str(sorted(["ICMP", p[scapy_all.IP].src, p[scapy_all.IP].dst, p[scapy_all.ICMP].code, p[scapy_all.ICMP].type, p[scapy_all.ICMP].id], key=str))
                else:
                    sess = str(sorted(["IP", p[scapy_all.IP].src, p[scapy_all.IP].dst, p[scapy_all.IP].proto], key=str))
            elif 'ARP' in p:
                sess = str(sorted(["ARP", p[scapy_all.ARP].psrc, p[scapy_all.ARP].pdst], key=str))
            else:
                sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
        return sess

    def get_conversations(self):
        return self.conversations
