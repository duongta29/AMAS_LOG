from elasticsearch import Elasticsearch
from datetime import datetime
import re

es = None
index_server = "virustotal_sample"
index_alias = "vt-alias"
doc_type_server = '_doc'
def init_db_insert():
    global es
    es=Elasticsearch([{'host':"127.0.0.1",'port':9200}])
def process_name(name):
    name_out = ""
    if name == None:
        return name
    name_list = re.findall(r"[\w']+", name)
    for x in name_list:
        try:
            a = int(x)
            continue
        except:
            pass
        
        try:
            a = int(x, 16)
            continue
        except: 
            pass
        if len(x) < 3:
            continue
        if name_out == "":
            name_out = x
        else:
            name_out += "." + x
    
    if name_out == "":
        name_out = "special_name"
    return name_out

def process_candidate(candidate, type, name, type_more, name_detail, av):
    candidate['malware_type'] = type
    candidate['malware_name'] = name
    candidate['name_detail'] = name_detail
    candidate['av'] = av
    candidate['type_more'] = type_more
    candidate['tag'] = candidate['tags']
    timestamp = candidate['timestamp']
    try:
        timestamp = int(timestamp)
        dt_object = datetime.fromtimestamp(timestamp)
    except:
        dt_object = datetime.now()
    time_string = dt_object.strftime('%Y-%m-%d %H:%M:%S')
    candidate['time_stamp'] = time_string
    candidate['report_name'] = dict()
    for x in candidate['report']:
        candidate['report_name'][x] = process_name(candidate['report'][x][0])
    return candidate

def process_candidate2(candidate):
    candidate['report_name'] = dict()
    for x in candidate['report']:
        candidate['report_name'][x] = process_name(candidate['report'][x][0])
    return candidate

def insert_candidate(candidate, type, name, type_more, name_detail, av):
    candidate = process_candidate(candidate, type, name, type_more, name_detail, av)
    """
    try:
        res = es.index(index=index_server,doc_type=doc_type_server,id=candidate['sha256'],body=candidate)
    except Exception as ex:
        print(ex)
        return candidate
    print(res)
    """
    return candidate

def insert_new_candidate(candidate):
    del candidate["link"]
    del candidate['report']
    del candidate['report_name']
    try:
        res = es.index(index=index_alias,id=candidate['sha256'],body=candidate)
    except Exception as ex:
        print(ex)
    # print(res)