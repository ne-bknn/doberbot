import pandas as pd
from sklearn.manifold import TSNE

def tsne_transformer(df): 
    embedded = TSNE(n_components=2).fit_transform(df)
    return embedded
