# doberbot
http clusterization and vizualization tool

Usage:
To view demo, do 
```bash
pip install -r requirements.txt
python app.py
```

![interface demo](https://raw.githubusercontent.com/ne-bknn/doberbot/main/image.png)

Architecture:

`loaders.py` - loader interface and implementations for pcaps (Packmate's Postgres should be implemented, too)

`analyzer` - analyzer module that does the heavy lifting

`research` - colab notebooks with r&d details

## The idea:
1. Load streams from given data source
2. Extract features, prepare them a bit: LSH arguments and cluster 'em, hash user agents, some ad-hoc engineering (like specify presense of potentially malicious charachters in parameters)
3. Put given stream in a space defined by extracted features
4. Reduce dimensions down to 2/3 (t-SNE or PCA)
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

## Iteration 2:
1. Features are normalized
2. t-SNE reduces dimensiality down to 3
3. 3D-viewer based on Dash

Current problems and todos:
The results are still incomprehensible; moreover, they are non-reproducible. Some todos are from previous iteration:
1. Filter out garbage features.
2. Mine HTTP packets for more features. Fourth iteration may introduce seq2seq approach for generating feature vector, but research is needed. 
3. Web interface is much better than sns plots, still not very fun to use. Should work on usability.
4. Testing on new datasets; the only pcap I was testing on is a bit specific. Something like API calls may be handled better. And loader should be made more robust. 
5. Maybe PCA instead of t-SNE? It is at least somehow interpretable and reproducible.
6. Should refactor the code in third iteration, it is already messy.
