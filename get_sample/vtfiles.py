#!/usr/bin/python
#
# Copyright 2012 Google Inc. All Rights Reserved.

"""Simple script to interact with VirusTotal's file distribution API.

VirusTotal's file distribution API allows privileged users to download files
submitted to VirusTotal. It works over HTTP and makes use of json objects to
send back basic information on the submitted files that will allows the
client-side to decide whether a given file under consideration should be
downloaded. The API is documented at:
https://www.virustotal.com/documentation/private-api/#file-feed
"""


import calendar
import json
import logging
import os
try: 
    import queue
except ImportError:
    import Queue as queue
import re
import socket
import sys
import threading
import time
import sys
import requests
import pefile

if sys.version_info[0] == 3:
  import urllib.request as urllib
else:
  import urllib
#import urllib
import datetime
from config import Config
#from send_mail import mail_sender
from db_insert import insert_candidate, init_db_insert, insert_new_candidate
from sample_insert import insert_sample, init_db_insert_sample
from sample_classify import process_sample
import shutil

API_KEY = 'a50869dfe068d7f1a1d5d81e617186e23e1cef6d95d8ac11d6f0594f883f6877'  # Insert your API here
API_URL = ('https://www.virustotal.com/vtapi/v2/file/distribution'
           '?after=%s&limit=%s&apikey=%s&reports=true')
API_BATCH_SIZE = 1000

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

NUM_CONCURRENT_DOWNLOADS = 20
MAX_DOWNLOAD_ATTEMPTS = 3
LOCAL_STORE = 'vtfiles'

HEX_CHARACTERS = 'abcdef0123456789'

socket.setdefaulttimeout(10)

LOGGING_LEVEL = logging.INFO  # Modify if you just want to focus on errors
logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    stream=sys.stdout)

report_json = {}
WriteCheck = False
def load_report_json():
  global report_json
  filename = 'data/{:%Y-%m-%d}.report'.format(datetime.datetime.now())
  if os.path.isfile(filename):
    with open(filename, 'r') as json_file:
      report_json = json.load(json_file)

def export_report():
  global WriteCheck
  filename = 'data/{:%Y-%m-%d}.report'.format(datetime.datetime.now())
  time_check = datetime.datetime.now()
  if time_check.minute < 1:
    if WriteCheck == False:
      WriteCheck = True
      with open(filename, 'w') as json_file:
        json.dump(report_json, json_file)
  else:
    WriteCheck = False
class VTSampleDownload:
  def __init__(self, key):
    self.api_key = key
    self.type = NONE_TYPE

  def set_local_store(self, local_path):
    self.local_store = local_path
    self.store_path = local_path

  def set_massive(self, massvice_path, enable):
    self.folder_massive = os.path.join(self.local_store, massvice_path)
    self.enable_massive = enable

  def set_adware(self, adware_path, enable):
    self.folder_adware = os.path.join(self.local_store, adware_path)
    self.enable_adware = enable

  def set_pub(self, pub_path, enable):
    self.folder_pub = os.path.join(self.local_store, pub_path)
    self.enable_pub = enable

  def set_html(self, html_path, enable):
    self.folder_html = os.path.join(self.local_store, html_path)
    self.enable_html = enable
  
  def set_pdf(self, pdf_path, enable):
    self.folder_pdf = os.path.join(self.local_store, pdf_path)
    self.enable_pdf = enable

  def set_virus(self, virus_path, enable):
    self.folder_virus = os.path.join(self.local_store, virus_path)
    self.enable_virus = enable

  def set_android(self, android_path, enable):
    self.folder_android = os.path.join(self.local_store, android_path)
    self.enable_android = enable
  
  def set_csharpe(self, csharpe_path, enable):
    self.folder_csharpe = os.path.join(self.local_store, csharpe_path)
    self.enable_csharpe = enable
  
  def create_local_store(self):
    # create not less detect
    config = Config()
    root_folder = config.get('path', 'local_store')
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

    if not os.path.exists(root_folder):
      os.mkdir(root_folder)
    if not os.path.exists(massive_folder):
      os.mkdir(massive_folder)
    if not os.path.exists(adware_folder):
      os.mkdir(adware_folder)
    if not os.path.exists(pub_folder):
      os.mkdir(pub_folder)
    if not os.path.exists(html_folder):
      os.mkdir(html_folder)
    if not os.path.exists(virus_folder):
      os.mkdir(virus_folder)
    if not os.path.exists(android_folder):
      os.mkdir(android_folder)
    if not os.path.exists(Csharpe_folder):
      os.mkdir(Csharpe_folder)
    if not os.path.exists(pdf_folder):
      os.mkdir(pdf_folder)
    if not os.path.exists(not_detect_folder):
      os.mkdir(not_detect_folder)
    if not os.path.exists(big_file_folder):
      os.mkdir(big_file_folder)
    if not os.path.exists(nonetype_folder):
      os.mkdir(nonetype_folder)
    if not os.path.exists(PE64_folder):
      os.mkdir(PE64_folder)
    
    root_folder = config.get('path', 'local_store')
    less_detect_folder = os.path.join(root_folder, config.get('path', 'less_detect'))
    root_folder = less_detect_folder
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

    if not os.path.exists(root_folder):
      os.mkdir(root_folder)
    if not os.path.exists(massive_folder):
      os.mkdir(massive_folder)
    if not os.path.exists(adware_folder):
      os.mkdir(adware_folder)
    if not os.path.exists(pub_folder):
      os.mkdir(pub_folder)
    if not os.path.exists(html_folder):
      os.mkdir(html_folder)
    if not os.path.exists(virus_folder):
      os.mkdir(virus_folder)
    if not os.path.exists(android_folder):
      os.mkdir(android_folder)
    if not os.path.exists(Csharpe_folder):
      os.mkdir(Csharpe_folder)
    if not os.path.exists(pdf_folder):
      os.mkdir(pdf_folder)
    if not os.path.exists(not_detect_folder):
      os.mkdir(not_detect_folder)
    if not os.path.exists(big_file_folder):
      os.mkdir(big_file_folder)
    if not os.path.exists(nonetype_folder):
      os.mkdir(nonetype_folder)
    if not os.path.exists(PE64_folder):
      os.mkdir(PE64_folder)
    
  def current_after(self):
    """Retrieves the current after value from persistent storage.

    VirusTotal's distribution API is based on a sliding window approach with and
    after parameters that allows you to paginate over all the files submitted
    after a given timestamp. The first time this script is launched the current
    after is read from disk.

    Returns:
      Last after value stored in disk, as a string. If the script was never
      launched before or the script's memory was deleted it will return the
      current timestamp minus 3 hours.
    """
    after = ''
    if os.path.exists('vtfiles.memory'):
      # Retrieve the stored after pointer.
      with open('vtfiles.memory', 'r') as memory:
        after = memory.read().strip()

    if not re.match('[0-9]+$', after):
      # We do not know where we were at, just fix after to be 3 hours before the
      # current GMT epoch.
      after = '%s' % ((calendar.timegm(time.gmtime()) - 3 * 3600) * 1000)

    return after


  def store_after(self, after):
    """Stores the current after value to disk.

    Every so often the current sliding window pointer is stored to disk in order
    to make sure that if the script is stopped or dies it will know where to
    start at the next time it is launched.

    Args:
      after: after value (string) to save in a memory file.
    """
    with open('vtfiles.memory', 'w') as memory:
      memory.write(after)


  def get_download_candidates(self, after=0, limit=API_BATCH_SIZE):
    """Asks VirusTotal's file feed API for files to download.

    Interacts with:
      https://www.virustotal.com/documentation/private-api/#file-feed
    Asking for files in a given distribution queue that have arrived to VirusTotal
    after the timestamp <after>. The API answers back with a json object per
    queued file, the json object contains basic information about the file as well
    as a link to download it.

    Args:
      after: timestamp that filters the items to retrieve, only files submitted
        after this timestamp will be retrieved.
      limit: number of items to retrieve from the queue that comply with the
        previous condition.

    Returns:
      List of json objects containing the basic information about each file
      retrieved. None if there was an error with the request.
    """
    try:
      response = requests.get(API_URL % (after, limit, self.api_key))
      response = response.text
    # Should not catch such a general exception, but who knows what can go
    # on in the client-side.
    except Exception as ex:
      print(ex)
      logging.error(ex)
      #send_mail(str(ex))
      return

    try:
      candidates = json.loads(response)
    except ValueError:
      return

    return candidates


  def detection_ratio(self, report):
    """Calculates the detection ratio of a given VirusTotal scan report.

    Processes the report dictionary structure of the file distribution API call
    response and produces a number of positives and a total number of engines
    tha scanned the file.

    Args:
      report: AV scan dictionary structure, as returned by the file distribution
        API call.

    Returns:
      Tuple with two items, the first one being the number of AV solutions that
      detected the file and the second one being the total number of AV engines
      that scanned it. Returns None if the report is not valid.
    """
    if not report:
      return

    total = len(report)
    positives = len([x[0] for x in report.values() if x[0] and x[0] != '-'])
    return (positives, total)

  def filter_candidate(self, candidate):
    """Decides whether a given download candidate should be downloaded.

    This function allows the user to parametrize the files he is interested in
    and download exclusively those. For example, certain users might only want
    to download Portable Executable files, others may only be interested in files
    with more than N positives, etc.

    Args:
      candidate: dictionary with basic information on a file received at
        VirusTotal.

    Returns:
      True if the canidate should be ignored and not downloaded, False if it
      meets our requirements and it must be downloaded.
    """
    name = ""
    # Filters candidates with less than 2 positives
    a = type(candidate)
    report = candidate.get('report')
    
    # with open(candidate.get('sha256') + '.txt', 'w') as outfile:
    #     json.dump(candidate, outfile)
    if report and self.detection_ratio(report)[0] < 5:
      return "", LESS_DETECT, name
    # Filter candidates with a size over 32MB
    if candidate.get('size', 0) > 32 * 1024 * 1024:
      return "", FILE_BIG, name

    store_path = ""
    malware_name = ""
    sample_type = AV_NOT_DETECT
    try:
      sample_type, malware_name = self.check_PE(candidate)
    except:
      pass
    if sample_type != NONE_TYPE and sample_type != AV_NOT_DETECT:
      name = self.get_sample_name(malware_name)
      if sample_type == MASSIVE:
        store_path = os.path.join(self.store_path,self.folder_massive, name)
      elif sample_type == ADWARE:
        store_path = os.path.join(self.store_path,self.folder_adware, name)
      elif sample_type == PUB:
        store_path = os.path.join(self.store_path,self.folder_pub, name)
      elif sample_type == VIRUS:
        store_path = os.path.join(self.store_path,self.folder_virus, name)
    
    if sample_type != NONE_TYPE and sample_type != AV_NOT_DETECT:
      return False, store_path, sample_type, name

    try:
      sample_type, malware_name = self.check_android(candidate)
    except:
      pass
    if sample_type != NONE_TYPE and sample_type != AV_NOT_DETECT:
      name = self.get_sample_name(malware_name)
      if sample_type == ANDROID:
        store_path = os.path.join(self.store_path,self.folder_android, name)

    if sample_type != NONE_TYPE and sample_type != AV_NOT_DETECT:
      return False, store_path, sample_type, name
    try:
      sample_type, malware_name = self.check_pdf(candidate)
    except:
      pass
    if sample_type != NONE_TYPE and sample_type != AV_NOT_DETECT:
      name = self.get_sample_name(malware_name)
      if sample_type == PDF:
        store_path = os.path.join(self.store_path,self.folder_pdf, name)
    if sample_type != NONE_TYPE and sample_type != AV_NOT_DETECT:
      return False, store_path, sample_type, name
    
    try:
      sample_type, malware_name = self.check_html(candidate)
    except:
      pass
    if sample_type != NONE_TYPE and sample_type != AV_NOT_DETECT:
      name = self.get_sample_name(malware_name)
      if sample_type == HTML:
        store_path = os.path.join(self.store_path,self.folder_html, name)
    if sample_type != NONE_TYPE and sample_type != AV_NOT_DETECT:
      return False, store_path, sample_type, name
    return True, store_path, sample_type, name

  def write_data(self, data):
    filename = 'data/{:%Y-%m-%d}.hash'.format(datetime.datetime.now())
    f = open(filename, 'a')
    f.write(data)
    f.write('\n')
    f.close()

  def write_info(self, candidate, target):
    with open(target, 'w') as f:
      f.write('SHA256:' + str(candidate.get('sha256')) + "\n")
      f.write('Type:' + str(candidate.get('type')) + "\n")
      reports = candidate.get('report')
      for report in reports:
        f.write(report + ":"+ str(reports[report][0]) + "\n")

  def check_download_condition(self, malware_type):
    config = Config()
    if int(config.get('save', 'download_sample')) == 0:
      return False
    
    if malware_type == NONE_TYPE:
      if int(config.get('save', 'nonetype')) == 1:
        return True
    
    if malware_type == MASSIVE:
      if int(config.get('save', 'massive')) == 1:
        return True
    
    if malware_type == ADWARE:
      if int(config.get('save', 'adware')) == 1:
        return True
    
    if malware_type == PUB:
      if int(config.get('save', 'pub')) == 1:
        return True
    
    if malware_type == HTML:
      if int(config.get('save', 'html')) == 1:
        return True
    
    if malware_type == PDF:
      if int(config.get('save', 'pdf')) == 1:
        return True
    
    if malware_type == VIRUS:
      if int(config.get('save', 'virus')) == 1:
        return True
    
    if malware_type == ANDROID:
      if int(config.get('save', 'android')) == 1:
        return True
    
    if malware_type == CSHARPE:
      if int(config.get('save', 'Csharpe')) == 1:
        return True
      
    if malware_type == LESS_DETECT:
      if int(config.get('save', 'LESS_DETECT')) == 1:
        return True
    
    if malware_type == FILE_BIG:
      if int(config.get('save', 'file_big')) == 1:
        return True
    
    if malware_type == AV_NOT_DETECT:
      if int(config.get('save', 'not_detect')) == 1:
        return True

    return False
  def get_pe64(self, candidate, download, file, sha256):
    config = Config()
    root_folder = config.get('path', 'local_store')
    pe64_folder  = os.path.join(root_folder, config.get('path', 'PE64'), candidate['malware_name'])
    
    if download:
      pe = pefile.PE(file)
      pe_type = pe.PE_TYPE
      pe.close()
      if pe_type == 523:
        pe.close()
        if not os.path.exists(pe64_folder):
          os.mkdir(pe64_folder)
        dest_file = os.path.join(pe64_folder,sha256)
        shutil.copyfile(file, dest_file)
        a = str(file) + '.txt'
        b= str(dest_file) + '.txt'
        shutil.copyfile(str(file) + '.txt', str(dest_file) + '.txt')
    else:
      file = "sample_temp\\" + sha256
      download_url = candidate.get('link')
      urllib.urlretrieve(download_url, file)
      self.write_info(candidate, str(file)+".txt")
      pe = pefile.PE(file)
      pe_type = pe.PE_TYPE
      pe.close()
      if pe_type == 523:
        if not os.path.exists(pe64_folder):
          os.mkdir(pe64_folder)
        dest_file = os.path.join(pe64_folder,sha256)
        shutil.copyfile(file, dest_file)
        shutil.copyfile(str(file) + '.txt', str(dest_file) + '.txt')
      os.remove(file)
      os.remove(str(file)+".txt")

  def check_disk_space(self, store_path):
    try:
      stat = shutil.disk_usage(store_path) 
      if (stat.free / stat.total)*100 > 10:
        return True
    except Exception as ex:
      print(ex)
    return False

  def download_candidate(self, candidate, store_path, malware_type):
    """Downloads a given file from VirusTotal to the local store.

    Files are stored locally in a 3 level directory structure in order to avoid
    acess latency.

    Args:
      candidate: dictionary with basic information on a file received at
        VirusTotal.

    Returns:
      True if the file was successfully downloaded, False if not.
    """
    if not 'link' in candidate or not 'md5' in candidate:
      return False

    """
    sha256 = candidate.get('md5')
    write_data(sha256)
    return True
    """

    download_url = candidate.get('link')
    sha256 = candidate.get('sha256')
    target = os.path.join(store_path,sha256)
    attempts = 0
    config = Config()
    path_check = config.get('path', 'local_store')
    download = self.check_download_condition(malware_type)
    while attempts < MAX_DOWNLOAD_ATTEMPTS:
      try:
        if int(download) and self.check_disk_space(path_check):
          if not os.path.exists(store_path):
            os.mkdir(store_path)
          urllib.urlretrieve(download_url, target)
          self.write_info(candidate, str(target)+".txt")
        
        # Check PE 64 or C#
        if int(config.get('save', 'PE64')) == 1 and (malware_type == MASSIVE or malware_type == ADWARE or malware_type == PUB or malware_type == VIRUS) and self.check_disk_space(path_check):
          self.get_pe64(candidate, download, target, sha256)
              
              # copy to PE 64:

        return True
      # Should not catch such a general exception, but who knows what can go
      # on in the client-side.
      except Exception as ex:
        attempts += 1
    return False


  def process_candidate(self, candidate):
    """Allows the user to perform a custom action with the downloaded file.

    This function is called after a file has been successfully downloaded to the
    local store. It might be used to insert the file data into a local database,
    to trigger another process, etc. My recommendation is that this function
    should be as lightweight and quick as possible so that the download process
    is not delayed, hence, anything you do here should be done asynchronously.
    You might want to launch an asynchronous thread or some external process and
    return immediatelly.

    Args:
      candidate: dictionary with basic information on a file received at
        VirusTotal.

    Returns:
      True if the post-processing was successful, False if not.
    """
    return True


def main():
  """Main routine, thread pool to retrieve VT files and download them."""
  logging.info('Initializing VirusTotal file feed downloader')
  logging.info('Creating local store if necessary')
  #init_db_insert()
  #init_db_insert_sample()
  config = Config()
  #load_report_json()
  vt_download = VTSampleDownload("b39c0fb1c56dd959f6b217c24a9c43e27e3a0b7192fd4e9eb39e7cbbbab9cb14")
  vt_download.set_local_store(str(config.get('path', 'local_store')))
  vt_download.set_massive(str(config.get('path', 'massive')),config.get('enable', 'massive'))
  vt_download.set_adware(str(config.get('path', 'adware')),config.get('enable', 'adware'))
  vt_download.set_pub(str(config.get('path', 'pub')),config.get('enable', 'pub'))
  vt_download.set_html(str(config.get('path', 'html')),config.get('enable', 'html'))
  vt_download.set_pdf(str(config.get('path', 'pdf')),config.get('enable', 'pdf'))
  vt_download.set_virus(str(config.get('path', 'virus')),config.get('enable', 'virus'))
  vt_download.set_android(str(config.get('path', 'android')),config.get('enable', 'android'))
  vt_download.set_csharpe(str(config.get('path', 'csharpe')),config.get('enable', 'csharpe'))
  vt_download.create_local_store()

  work = queue.Queue()  # Queues download candidates
  end_process = False

  def worker():
    while not end_process:
      mail_send_error = False
      try:
        logging.info("queue size: " + str(work.qsize()))
        candidate = work.get(True, 5)
      except queue.Empty:
        logging.info('queue empty')
        continue
      # try:
      sha256 = candidate.get('sha256', 'file').lower()
      logging.info('Handling download candidate %s', sha256)
      #check, store_path, malware_type, malware_name = vt_download.filter_candidate(candidate)
      store_path, info = process_sample(candidate)

      malware_type = None
      malware_name = None
      type_more = None
      name_detail = None
      av = None

      if 'malware_type' in info:
        malware_type = info['malware_type']
      if 'family_name' in info:
        malware_name = info['family_name']
      if 'detect_by' in info:
        av = info['detect_by']
      if 'malware_type_more' in info:
        type_more = info['malware_type_more']
      if 'malware_name' in info:
        name_detail = info['malware_name']

      sample_info = insert_candidate(candidate, malware_type, malware_name, type_more, name_detail, av)
      #insert_sample(sample_info)
      #export_report()
      logging.info('Downloading %s', sha256)
      success = vt_download.download_candidate(candidate, store_path, malware_type)          
      if success:
        logging.info('%s download successful', sha256)
        logging.info('Post-processing %s', sha256)
        success = vt_download.process_candidate(candidate)
        if success:
          logging.info('%s post-processing was sucessful', sha256)
        else:
          logging.error('%s post-processing failed', sha256)
      else:
        logging.error('%s download failed', sha256)
      insert_new_candidate(sample_info)
      # except Exception as ex:
      #   if mail_send_error == False:
      #     mail_sender(str(ex))
      #     mail_send_error = True
      #   print(ex)
      work.task_done()

  threads = []
  for unused_index in range(NUM_CONCURRENT_DOWNLOADS):
    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()
    threads.append(thread)

  logging.info('Retrieving current sliding window pointer')
  after = vt_download.current_after()
  iterations = 0
  count = 0
  send_mail_running = False
  while not end_process:
    try:
      time_check = datetime.datetime.now()
      if time_check.minute < 5:
        if send_mail_running == False:
          #mail_sender("download still running ok")
          send_mail_running = True
      else:
        send_mail_running = False
      if work.qsize() > 300:
        logging.info('Too many files waiting to be downloaded, sleeping')
        count += 1
        if count == 20:
          #mail_sender("Too many files waiting to be downloaded, exiting")
          sys.exit("Too many files waiting to be downloaded, exiting")
        time.sleep(30)
        continue
      count = 0
      logging.info('Retrieving download candidates received after %s', after)
      candidates = vt_download.get_download_candidates(after)
      if candidates is None:
        logging.error('Could not retrieve download candidates')
        time.sleep(10)
        continue
      if candidates:
        iterations += 1
        after = '%s' % candidates[-1].get('timestamp')
        logging.info('Retrieved %s candidates, queuing them', len(candidates))
        for candidate in candidates:
          work.put(candidate)
      else:
        logging.info('No more download candidates, sleeping')
        time.sleep(30)
      if iterations == 2:  # Every once in a while store current after
        vt_download.store_after(after)
        iterations = 0
    except KeyboardInterrupt:
      end_process = True
      logging.info('Stopping the downloader, current downloads must end, '
                   'please wait...')
      for thread in threads:
        if thread.is_alive():
          thread.join()

if __name__ == '__main__':
  logging.basicConfig(
    filename='logs.log',
    level=logging.INFO,
    format='%(asctime)s - %(module)s - %(funcName)s: [%(levelname)s] %(message)s'
  )
  main()
