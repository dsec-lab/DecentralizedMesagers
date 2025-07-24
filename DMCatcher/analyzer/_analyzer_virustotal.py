# coding=utf-8
__author__ = 'lihao'

import sys

import pandas as pd
import json
import logging
import collections
from collections import Counter
from netaddr import *
import os

import pycountry_convert as pc
from pycountry_convert.convert_country_alpha2_to_continent_code import COUNTRY_ALPHA2_TO_CONTINENT_CODE

# from figures_plot.plot_figures import asn_draw


logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a')


class VirusTotalAnalyzer(object):
    def __init__(self):
        self.malicious_IPs = []

        self.already_ip_list = []
        self.city_list = list()
        self.country_name_list = list()
        self.hostname_list = list()

        self.asn_route_list = list()
        self.asn_domain_list = list()
        self.asn_type_list = list()
        self.asn_list = []

        self.ipv4_prefix_16 = []
        self.ipv4_prefix_24 = []

    def virustotal_report_analyzer(self, file_path):
        self.virustotal_report_file = file_path

        with open(self.virustotal_report_file, 'r', encoding='utf-8') as f:
            virustotal_response = json.load(f)['data']
            id = virustotal_response['id']
            attributes = virustotal_response['attributes']
            attributes_keys = list(attributes.keys())
            # print(attributes_keys)
            if 'asn' in attributes_keys:
                asn = attributes['asn']
                as_owner = attributes['as_owner']
            if 'whois' in attributes_keys:
                whois = attributes['whois']
                # print(whois)
            if 'last_https_certificate' in attributes_keys:
                last_https_certificate = attributes['last_https_certificate']
            total_votes = attributes['total_votes']
            last_analysis_stats = attributes['last_analysis_stats']
            if last_analysis_stats['malicious'] > 0:
                # print(id, asn, as_owner, last_analysis_stats)
                for i in range(last_analysis_stats['malicious']):
                    self.malicious_IPs.append(id)

    def print_info(self):
        print("Malicious IP List: ", len(Counter(self.malicious_IPs)),
              Counter(self.malicious_IPs).most_common(10))

    def virustotal_communicating_files_analyzer(self, file_path):
        self.virustotal_communicating_files_path = file_path
        with open(self.virustotal_communicating_files_path, 'r', encoding='utf-8') as f:
            data  = json.load(f)['data']  # Currently, when using VT for detection, the default maximum number is 10.
            for idx, virustotal_response in enumerate(data):
                if 'attributes' not in virustotal_response.keys():
                    continue
                id = virustotal_response['id']  # file id
                attributes = virustotal_response['attributes']
                attributes_keys = list(attributes.keys())
                total_votes = attributes['total_votes']
                if 'names' in attributes_keys:
                    names = attributes['names']
                if 'meaningful_name' in attributes_keys:
                    meaningful_name = attributes['meaningful_name']
                if 'pe_info' in attributes_keys:
                    pe_info = attributes['pe_info']
                    # print(idx, id, pe_info.keys())
                    if 'overlay' in pe_info.keys():
                        overlay = pe_info['overlay']  #
                    if 'sections' in pe_info.keys():
                        sections = pe_info['sections']
                        for section in sections:
                            pass
                            # print(section)
                if 'type_tags' in attributes_keys:
                    type_tags = attributes['type_tags']
                if 'type_description' in attributes_keys:
                    type_description = attributes['type_description']
                if 'tags' in attributes_keys:
                    tags = attributes['tags']
                if 'magic' in attributes_keys:
                    magic = attributes['magic']
                if 'last_analysis_stats' in attributes_keys:
                    last_analysis_stats = attributes['last_analysis_stats']
                if 'popular_threat_classification' in attributes_keys:
                    popular_threat_classification = attributes['popular_threat_classification']

    def virustotal_referrer_files_analyzer(self, file_path):
        self.virustotal_referrer_files_path = file_path
        with open(self.virustotal_referrer_files_path, 'r', encoding='utf-8') as f:
            data  = json.load(f)['data']  # Currently, when using VT for detection, the default maximum number is 10.
            for idx, virustotal_response in enumerate(data):
                if 'attributes' not in virustotal_response.keys():
                    continue
                id = virustotal_response['id']  # file id
                attributes = virustotal_response['attributes']
                attributes_keys = list(attributes.keys())
                total_votes = attributes['total_votes']
                if 'names' in attributes_keys:
                    names = attributes['names']
                if 'meaningful_name' in attributes_keys:
                    meaningful_name = attributes['meaningful_name']
                if 'pe_info' in attributes_keys:
                    pe_info = attributes['pe_info']
                    if 'overlay' in pe_info.keys():
                        overlay = pe_info['overlay']  # 
                    if 'sections' in pe_info.keys():
                        sections = pe_info['sections']
                        for section in sections:
                            pass
                            # print(section)
                if 'type_tags' in attributes_keys:
                    type_tags = attributes['type_tags']
                if 'type_description' in attributes_keys:
                    type_description = attributes['type_description']
                if 'tags' in attributes_keys:
                    tags = attributes['tags']
                if 'magic' in attributes_keys:
                    magic = attributes['magic']
                if 'last_analysis_stats' in attributes_keys:
                    last_analysis_stats = attributes['last_analysis_stats']
                    print(idx, id, last_analysis_stats)
                if 'popular_threat_classification' in attributes_keys:
                    popular_threat_classification = attributes['popular_threat_classification']


if __name__ == '__main__':
    # *********************************
    # step01: load ip data we collected
    # *********************************
    ip_data_dir = r'./ip_data'
    _list_berty_ips_ = list(
        pd.read_csv(os.path.join(ip_data_dir, r'berty-ips-2025-04-04.csv'), header=None).to_numpy()[:, -1])
    _list_jami_ips_ = list(
        pd.read_csv(os.path.join(ip_data_dir, r'jami-ips-2025-03-28.csv'), header=None).to_numpy()[:, -1])
    _list_matrix_ips_ = list(
        pd.read_csv(os.path.join(ip_data_dir, r'matrix-ips-2025-03-28.csv'), header=None).to_numpy()[:, -1])
    _list_status_ips_ = list(
        pd.read_csv(os.path.join(ip_data_dir, r'status-ips-2025-03-28.csv'), header=None).to_numpy()[:, -1])
    # *******************************
    # step02: load virustotal ip reports we detected
    # *******************************
    virustotal_report_data_dir = r'\DecentralizedMessagers\DataNeedToAnalysis\virustotal_ip_report'
    virustotal_analyzer = VirusTotalAnalyzer()
    for file_name in os.listdir(virustotal_report_data_dir):
        if file_name.endswith('.json'):
            ip = file_name[:-5]
            # select a messager: Matrix, Berty, Jami, Status
            if ip not in _list_jami_ips_: continue

            virustotal_report_file_path = os.path.join(virustotal_report_data_dir, file_name)
            try:
                virustotal_analyzer.virustotal_report_analyzer(virustotal_report_file_path)
            except Exception as e:
                print(e, end=' ')
                print(virustotal_report_file_path)
    virustotal_analyzer.print_info()
    # *******************************
    # step03: load virustotal ip communicating_files reports we detected
    # *******************************
    virustotal_communicating_files_data_dir = r'\DecentralizedMessager\decentralized_messagers\tools\virustotal_ip_communicating_files_report'
    for file_name in os.listdir(virustotal_communicating_files_data_dir):
        if file_name.endswith('.json'):
            ip = file_name[:-5]
            # select a messager: Matrix, Berty, Jami, Status
            if ip not in _list_berty_ips_: continue

            virustotal_communicating_files_path = os.path.join(virustotal_communicating_files_data_dir, file_name)
            try:
                virustotal_analyzer.virustotal_communicating_files_analyzer(virustotal_communicating_files_path)
            except Exception as e:
                print(e, end=' ')
                print(virustotal_communicating_files_path)
    # *******************************
    # step03: load virustotal ip communicating_files reports we detected
    # *******************************
    virustotal_referrer_files_data_dir = r'\DecentralizedMessager\decentralized_messagers\tools\virustotal_ip_referrer_files_report'
    for file_name in os.listdir(virustotal_referrer_files_data_dir):
        if file_name.endswith('.json'):
            ip = file_name[:-5]
            # select a messager: Matrix, Berty, Jami, Status
            if ip not in _list_berty_ips_: continue

            virustotal_referrer_files_path = os.path.join(virustotal_referrer_files_data_dir, file_name)
            try:
                virustotal_analyzer.virustotal_referrer_files_analyzer(virustotal_referrer_files_path)
            except Exception as e:
                print(e, end=' ')
                print(virustotal_referrer_files_path)
    sys.exit(-1)
