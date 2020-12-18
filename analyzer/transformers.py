import pandas as pd
from sklearn.manifold import TSNE

def tsne_transformer(df): 
    try:
        embedded = TSNE(n_components=3).fit_transform(df)
    except ValueError:
        print(df)
        raise

    return embedded
