from loaders import PcapLoader

p = PcapLoader("pcaps/stored_xss.pcapng")
d = p.get_conversations().to_pandas()
print(d)
