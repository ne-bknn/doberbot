from loaders import PcapLoader
from analyzer import create_features
from analyzer import tsne_transformer
from analyzer import debug_view

p = PcapLoader("pcaps/stored_xss.pcapng")
convs = p.get_conversations()
d = convs.to_pandas()
d1 = create_features(d.copy())
d2 = tsne_transformer(d1)
debug_view(d2)
