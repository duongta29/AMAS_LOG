from elasticsearch import Elasticsearch
from datetime import datetime
import re

es = None
index_server = "sample"
doc_type_server = '_doc'
def init_db_insert_sample():
    global es
    es=Elasticsearch([{'host':"127.0.0.1",'port':9200}])

def process_candidate(candidate):
    try:
        if candidate['report_name']['Microsoft'] == None:
            return None
    except:
        return None
    
    sample = {}
    sample['virus_name'] = 'Heur.' + candidate['report_name']['Microsoft']
    ssdeep_value = candidate['ssdeep']
    chunksize, chunk, double_chunk = ssdeep_value.split(':')
    chunksize = int(chunksize)

    sample['chunk'] = chunk
    sample['chunksize'] = chunksize
    sample['double_chunk'] = double_chunk
    sample['sha256'] = candidate['sha256']
    sample['ssdeep'] = candidate['ssdeep']
    return sample

def insert_sample(candidate):
    sample = process_candidate(candidate)
    if sample == None:
        print("not Add:" + candidate['sha256'])
        return
    try:
        res = es.index(index=index_server,doc_type=doc_type_server,id=candidate['ssdeep'],body=sample)
    except Exception as ex:
        print(ex)
        return
    print(res)