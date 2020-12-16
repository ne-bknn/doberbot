import logging

import pandas as pd
import numpy as np

from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.cluster import AffinityPropagation

import nilsimsa

logging.basicConfig(level=logging.INFO)

CATEGORICAL_FIELDS = ["req_method", "req_uri", "req_version", "req_host", "req_ua", "req_accept_enc", "resp_version", "resp_code", "resp_server"]
LSH_FIELDS = ["req_data", "resp_data"]
NORMALIZE_FIELDS = ["req_payload_length", "resp_header_length"]
DROP_FIELDS = []

def categorize(df, column):
    df[column] = LabelEncoder().fit_transform(df[column])

def calc_hash(df, column) -> None:
    df[column+"_hash"] = [nilsimsa.Nilsimsa(c).hexdigest() for c in df[column]]
    DROP_FIELDS.append(column+"_hash")

def get_pairwise_distances(df, column_name):
    pairwise_distance = np.asarray([[nilsimsa.compare_digests(hash1, hash2) for hash1 in df[column_name+"_hash"]] for hash2 in df[column_name+"_hash"]])
    pairwise_distance = (128 - pairwise_distance) / 128
    return pairwise_distance

def cluster_aff_prop(df, pairwise_distance, column_name):
    aff = AffinityPropagation(affinity="precomputed", max_iter=1000, random_state=None)
    aff.fit(pairwise_distance)
    df[column_name+"_labels"] = aff.labels_
    DROP_FIELDS.append(column_name+"_hash")

def normalize(df, column_name):
    n = MinMaxScaler()
    df[column_name] = n.fit_transform(np.asarray(df[column_name]).reshape(-1, 1))

def create_features(df):
    for column_name in CATEGORICAL_FIELDS:
        categorize(df, column_name)
    
    logging.info("Categorized")

    for column_name in LSH_FIELDS:
        calc_hash(df, column_name)
        distances = get_pairwise_distances(df, column_name)
        cluster_aff_prop(df, distances, column_name)
        logging.info("Yet another clustering done")
    
    logging.debug(f"Columns: {df.columns}")
    logging.debug(f"Columns to drop: {LSH_FIELDS+DROP_FIELDS}")
    drop_fields = list(set(DROP_FIELDS))
    for column_name in LSH_FIELDS+drop_fields:
        df.drop(column_name, axis=1, inplace=True)
    
    for column_name in df.columns:
        df[column_name] = pd.to_numeric(df[column_name])

    df["req_payload_length"] = df["req_payload_length"].fillna(0)
    df["resp_header_length"] = df["resp_header_length"].fillna(0)

    for column_name in NORMALIZE_FIELDS:
        normalize(df, column_name)

    return df

