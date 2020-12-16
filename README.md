# doberbot
http clusterization and vizualization tool

Usage:
To view demo, do `python main.py`.

Architecture:

`loaders.py` - loader interface and implementations for pcaps (Packmate's Postgres should be implemented, too)

`analyzer` - analyzer module that does the heavy lifting

`research` - colab notebooks with r&d details

## The idea:
1. Load streams from given data source
2. Extract features, prepare them a bit: LSH arguments and cluster 'em, hash user agents, some ad-hoc engineering (like specify presense of potentially malicious charachters in parameters)
3. Put given stream in a space defined by extracted features
4. Reduce dimensions down to 2 (t-SNE or PCA)
5. Render the resulting space 

## Iteration 1:
1. Data is loaded from pcap to pandas dataframe
2. Some features are categorized; some left as is. 
3. For request and response body pairwise distance is computed by calculating locality-sensetive hashes, than AffinityPropagation clustering algorithm is applied. Cluster numbers are used as additional features.
4. The dataset is t-SNE'd. See [Clustering](https://colab.research.google.com/drive/1paqIuWSY2-DBC1v49aBZh2PF2f90fzq-?usp=sharing) notebook for additional info.

Current problems and todos: 
The results are incomprehensible. I see these additional steps that can be done to solve the problem:
1. Normalization: t-SNE is sensetive to the distance between points, so having fields that differ by order of magnitude is not OK. 
Upd.: Done, doesn't help.
2. Feature filtering: some features may be nonsensical for given dataset, but have enough variance to not be discarded by t-SNE. Have to engineer some algorithm to identify such features. 
Upd.: Currently do not know how to implement.
3. More features should be engineered from texts
4. Improve interface (ideal solution - web-app with interactive plots)
