from loaders import PcapLoader
from analyzer import create_features
from analyzer import tsne_transformer
from analyzer import debug_view

def main():
    p = PcapLoader("pcaps/stored_xss.pcapng")
    convs = p.get_conversations()
    dataframe, texts = convs.to_pandas()
    dataframe1 = create_features(dataframe.copy())
    embedded = tsne_transformer(dataframe1)
    return embedded, texts

if __name__ == "__main__":
    df, texts = main()
    debug_view(df)
