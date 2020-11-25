# doberbot
http clusterization and vizualization tool

In progress

`loaders.py` - loader interface and implementations for pcaps and Packmate's Postgres
`analyzer` - analyzer module that does the heavy lifting
`research` - colab notebooks with r&d details 
`app.py` - web app that renders the space

The idea:
1. Load streams from given data source
2. Extract features, prepare them a bit: LSH arguments, hash user agents, some ad-hoc engineering (like specify presense of potentially malicious charachters in parameters)
3. Put given stream in a space defined by extracted features
4. Find clusters of streams
5. Reduce dimensions down to 2 (t-SNE or PCA)
5. Render the resulting space 
