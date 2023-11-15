import json
import logging
import os
from config import Config
import re

av_dict = {
'Microsoft': 1,
'Kaspersky':2,
'BitDefender':3,
'ESET-NOD32':4,
'Symantec':5,
'McAfee':6,
'Fortinet':7,
'Invincea':8,
'TrendMicro':9,
'Ikarus':10,
'Endgame':11,
'F-Secure':12,
'AVG':13,
'FireEye':14,
'Cyren':15,
'CrowdStrike':16,
'DrWeb':17,
'Rising':18,
'Avira':19,
'Avast':20,
'McAfee-GW-Edition':21,
'Antiy-AVL':22,
'SymantecMobileInsight':23,
'GData':24,
'Emsisoft':25,
'MicroWorld-eScan':26,
'Ad-Aware':27,
'K7GW':28,
'Sangfor':29,
'Sophos':30,
'AhnLab-V3':31,
'ZoneAlarm':32,
'Arcabit':33,
'Trustlook':34,
'K7AntiVirus':35,
'eGambit':36,
'ALYac':37,
'VBA32':38,
'CAT-QuickHeal':39,
'ClamAV':40,
'Zillya':41,
'Tencent':42,
'VIPRE':43,
'Yandex':44,
'Jiangmin':45,
'SentinelOne':46,
'Avast-Mobile':47,
'Cylance':48,
'Malwarebytes':49,
'Webroot':50,
'NANO-Antivirus':51,
'Bkav':52,
'Qihoo-360':53,
'Comodo':54,
'TrendMicro-HouseCall':55,
'SUPERAntiSpyware':56,
'Panda':57,
'Baidu':58,
'TotalDefense':59,
'Zoner':60,
'ViRobot':61,
'AegisLab':62,
'Paloalto':63,
'Alibaba':64,
'Kingsoft':65,
'CMC':66,
'AVware':67,
'F-Prot':68,
'MAX':69,
'TheHacker':70,
'WhiteArmor':71,
'nProtect':72,
'Cybereason':73,
'APEX': 74,
'Cynet': 75,
'Acronis': 76,
'TACHYON': 77,
'MaxSecure': 78,
'BitDefenderTheta': 79,
'Elastic': 80,
'Gridinsoft': 81
}
NAME_PARTERN = '[./:![]'

NONE_TYPE = "NONE_TYPE"
MASSIVE = "MASSIVE"
ADWARE = "ADWARE"
PUB = "PUB"
HTML = "HTML"
PDF = "PDF"
VIRUS = "VIRUS"
ANDROID = "ANDROID"
CSHARPE = "CSHARP"
LESS_DETECT = 'LESS_DETECT'
FILE_BIG = "FILE_BIG"
AV_NOT_DETECT = "AV_NOT_DETECT"
PE64="PE64"

def get_malware_name(name):
    datas = re.split(NAME_PARTERN,name)
    if len(datas) == 0:
        return datas[0]
    index = 0
    name = "a"
    for data in datas:
        if index == 0:
            index += 1
            continue
        if len(data) > len(name):
            name = data
    return name

def get_name_info_sample(candidate):
    report = candidate["report"]
    info = dict()
    for x,y in report.items():
        if x not in av_dict:
            print("New AV: " + x)
            continue
        if y[0] == None:
            continue
        if "detect_by" in info:
            if av_dict[x] > av_dict[info['detect_by']]:
                continue
            info['detect_by'] = x
            info['malware_name'] = y[0].lower()
        else:
            info['detect_by'] = x
            info['malware_name'] = y[0].lower()
    try:
        info['family_name'] = get_sample_name(info['malware_name'])
        return info
    except:
        return dict()


def check_PE(candidate, info):
    if 'malware_name' not in info:
        return False, AV_NOT_DETECT    
    malware_name = info['malware_name']
    
    if 'exe' in candidate['type'].lower() or 'dll' in candidate['type'].lower():
      if 'adware' in malware_name:
        return True, ADWARE
        
      if 'not-a-virus' in malware_name or 'potentially unwanted' in malware_name or 'application' in malware_name:
        return True, PUB

      if "virus" in malware_name:
        return True, VIRUS
        
      return True, MASSIVE
    elif 'gzip' in candidate['type'].lower():
      if "win32" in malware_name or "win64" in malware_name:
        return True, MASSIVE
    
    return False, NONE_TYPE
  
def check_android(candidate, info):
    if 'malware_name' not in info:
        return False, AV_NOT_DETECT

    if 'android' not in candidate['type'].lower():
        return False, NONE_TYPE

    return True, ANDROID

def check_html(candidate, info):
    if 'malware_name' not in info:
        return False, AV_NOT_DETECT

    malware_name = info['malware_name']

    if 'html' in malware_name or 'js' in malware_name or 'vbs' in malware_name or 'script' in malware_name:
        return True, HTML
        
    return False, NONE_TYPE

def check_pdf(candidate, info):
    if 'malware_name' not in info:
        return False, AV_NOT_DETECT

    if ('pdf' in candidate['type'].lower()):
        return True, PDF
        
    return False, NONE_TYPE

def sample_classify(candidate):
    info = get_name_info_sample(candidate)

    if 'malware_name' not in info:
        return AV_NOT_DETECT, info

    check, malware_type = check_PE(candidate, info)
    if check:
      return malware_type, info

    check, malware_type = check_android(candidate, info)
    if check:
      return malware_type, info

    check, malware_type = check_pdf(candidate, info)
    if check:
      return malware_type, info

    check, malware_type = check_html(candidate, info)
    if check:
      return malware_type, info

    return NONE_TYPE, info

def process_sample(candidate):
    store_path = ""
    malware_type, info = sample_classify(candidate)
    info['malware_type'] = malware_type

    config = Config()
    #All folder
    root_folder = config.get('path', 'local_store')
    less_detect_folder = os.path.join(root_folder, config.get('path', 'less_detect'))
    if candidate["positives"] < 5:
      root_folder = less_detect_folder
      info['malware_type'] = LESS_DETECT
      info['malware_type_more'] = malware_type
    if candidate['size'] > 32 * 1024 * 1024:
        malware_type = FILE_BIG
        info['malware_type'] = malware_type

    massive_folder  = os.path.join(root_folder, config.get('path', 'massive'))
    adware_folder   = os.path.join(root_folder, config.get('path', 'adware'))
    pub_folder      = os.path.join(root_folder, config.get('path', 'pub'))
    html_folder     = os.path.join(root_folder, config.get('path', 'html'))
    virus_folder    = os.path.join(root_folder, config.get('path', 'virus'))
    android_folder  = os.path.join(root_folder, config.get('path', 'android'))
    Csharpe_folder  = os.path.join(root_folder, config.get('path', 'Csharpe'))
    pdf_folder      = os.path.join(root_folder, config.get('path', 'pdf'))
    not_detect_folder = os.path.join(root_folder, config.get('path', 'not_detect'))
    big_file_folder = os.path.join(root_folder, config.get('path', 'big_file'))
    nonetype_folder = os.path.join(root_folder, config.get('path', 'nonetype'))
    PE64_folder = os.path.join(root_folder, config.get('path', 'PE64'))

    if malware_type == NONE_TYPE:
        store_path = nonetype_folder
    if malware_type == MASSIVE:
        store_path = massive_folder
    if malware_type == ADWARE:
        store_path = adware_folder
    if malware_type == PUB:
        store_path = pub_folder
    if malware_type == HTML:
        store_path = html_folder
    if malware_type == PDF:
        store_path = pdf_folder
    if malware_type == VIRUS:
        store_path = virus_folder
    if malware_type == ANDROID:
        store_path = android_folder
    if malware_type == CSHARPE:
        store_path = Csharpe_folder
    if malware_type == LESS_DETECT:
        store_path = less_detect_folder
    if malware_type == FILE_BIG:
        store_path = big_file_folder
    if malware_type == AV_NOT_DETECT:
        store_path = not_detect_folder
    if malware_type == PE64:
        store_path = PE64_folder
    
    try:
        store_path = os.path.join(store_path, info['family_name'])
        return store_path, info
    except:
        return store_path, info
 
def get_sample_name(name_sample):
    name_out = ""
    name = name_sample
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
