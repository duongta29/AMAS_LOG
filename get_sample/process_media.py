from elasticsearch import Elasticsearch
from sample_insert import *
from db_insert import *
import time

es = None
def insert(dataload, index_server, doc_type_server):
    data = dataload['_source']
    if "report_name" not in data:
        data = process_candidate2(data)
    id = dataload['_id']
    insert_sample(data)
    data['get_ssdeep'] = 1
    res = es.index(index=index_server,doc_type=doc_type_server,id=id,body=data)
    print(res)

def get_data(query, index_server, doc_type_server):
    res= es.search(index=index_server,body=query)
    return res['hits']['hits']
init_db_insert_sample()
init_db_insert
while 1:
    defaultQuery = {"size":1000,"sort":{"time_stamp":"asc"},"query":{"query_string":{"query":"NOT (get_ssdeep: 1)","type":"phrase"}}}
    es=Elasticsearch([{'host':"127.0.0.1",'port':9200}])
    data = get_data(defaultQuery, "virustotal_sample", "_doc")
    for x in data:
        try:
            insert(x, "virustotal_sample", "_doc")
        except Exception as ex:
            print(ex)
            #time.sleep(5)
