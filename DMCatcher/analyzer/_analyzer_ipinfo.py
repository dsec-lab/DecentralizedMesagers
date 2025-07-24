# coding=utf-8
__author__ = 'lihao'

from json import JSONDecodeError
from itertools import combinations
import pandas as pd
import json
import logging
import collections
from collections import Counter
from netaddr import *
import os
import pycountry_convert as pc
from pycountry_convert.convert_country_alpha2_to_continent_code import COUNTRY_ALPHA2_TO_CONTINENT_CODE

import re
import tldextract

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a')

continents = {
    'NA': 'North America',
    'SA': 'South America',
    'AS': 'Asia',
    'OC': 'Australia',
    'AF': 'Africa',
    'EU': 'Europe'
}

cloud_provider_list = [
    'Amazon Web Services (AWS)',
    'Microsoft Azure',
    'Google Cloud (GCP—formerly Google Cloud Platform)',
    'IBM Cloud (formerly SoftLayer)',
    'Oracle Cloud',
    'CloudFlare',
    'Alibaba Cloud',
    'RedHat',
    'Heroku',
    'Digital Ocean',
    'Linode',
    'Cloudways',
    'Rackspace'
]


def save_data(data, file_name):
    pd.DataFrame(data).to_csv(file_name,header=None, index=None)
    return 0


class IpInfoAnalyzer(object):
    def __init__(self):
        self.city_list = list()
        self.country_name_list = list()
        self.hostname_list = list()
        self.org = list()
        self.as_ = list()
        self.ipv4_prefix_list = []
        self.ipv4_prefix_16 = []
        self.ipv4_prefix_24 = []

        self.continent_homeserver_ips = collections.defaultdict(list)

    def analyzer(self, file_path):
        self.ipinfo_response_file = file_path

        with open(self.ipinfo_response_file, 'r', encoding='utf-8') as f:
            ipinfo_response = json.load(f)
            ipinfo_response_keys = list(ipinfo_response.keys())
            # print(ipinfo_response_keys)

            ip = IPAddress(ipinfo_response['ip'])
            a, b, c, _ = str(ip).split('.')
            self.ipv4_prefix_16.append('.'.join([a, b]))
            self.ipv4_prefix_24.append('.'.join([a, b, c]))
            IPv4_prefix = ip.info['IPv4'][0]['prefix']
            self.ipv4_prefix_list.append(IPv4_prefix)

            if 'country_name' in ipinfo_response.keys():
                country_name = ipinfo_response['country_name']
                self.country_name_list.append(country_name)
            else:
                self.country_name_list.append(None)
            if 'country' in ipinfo_response.keys():
                country_code = ipinfo_response['country']
                if country_code in list(COUNTRY_ALPHA2_TO_CONTINENT_CODE.keys()):
                    continent_name = pc.country_alpha2_to_continent_code(country_code)
                    self.continent_homeserver_ips[continent_name].append(ipinfo_response['ip'])
            if 'city' in ipinfo_response_keys:
                self.city_list.append(ipinfo_response['city'])
            else:
                self.city_list.append(None)

            if 'hostname' in ipinfo_response_keys:
                self.hostname_list.append(ipinfo_response['hostname'])
                '''
                ext = tldextract.extract(ipinfo_response['hostname'])
                parts = ext.subdomain.split('.')
                if len(parts) >= 2:
                    subdomain = '.'.join(parts[-1:] + [ext.domain, ext.suffix])
                    print("subdomain: {}".format(subdomain))
                '''
            if 'org' in ipinfo_response_keys:
                self.org.append(ipinfo_response['org'])
                self.as_.append(ipinfo_response['org'].split(' ')[0])

    def print_info(self):
        print("Continent List:", end=' ')
        for key, values in self.continent_homeserver_ips.items():
            print(key, len(values), end=' ')
        print()
        print("Country List: ", len(Counter(self.country_name_list)), Counter(self.country_name_list).most_common(10))
        print("City Count: ", len(Counter(self.city_list)))
        print("IPv4 Prefix (/8, /16, /24):",
              len(Counter(self.ipv4_prefix_list)), Counter(self.ipv4_prefix_list).most_common(3),
              len(set(self.ipv4_prefix_16)), Counter(self.ipv4_prefix_16).most_common(3),
              len(set(self.ipv4_prefix_24)), Counter(self.ipv4_prefix_24).most_common(3),
              )
        print("Hostname List: ", len(Counter(self.hostname_list)),
              Counter(self.hostname_list).most_common(5))
        print("Org: ", len(Counter(self.org)),  Counter(self.org).most_common(5))
        print("AS: ", len(Counter(self.as_)),  Counter(self.as_).most_common(10))


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
    # ***********************************
    # step011: An IP corresponding to multi-Messagers
    # ***********************************
    # Find the public IP between any two groups
    common_in_three = set()
    lists = [_list_matrix_ips_, _list_berty_ips_, _list_jami_ips_, _list_status_ips_]
    for combo in combinations(lists, 2):  # All two group combinations
        intersection = set(combo[0]) & set(combo[1])
        common_in_three.update(intersection)  # 
    print("IPs that exist in at least two groups:", len(common_in_three))
    # *******************************
    # step02: load ipinfo we detected
    # *******************************
    ipinfo_data_dir = r'\DecentralizedMessagers\DataNeedToAnalysis\ipinfo_response'
    ipinfo_analyzer = IpInfoAnalyzer()
    for file_name in os.listdir(ipinfo_data_dir):
        if file_name.endswith('.json'):
            ip = file_name[:-5]
            # select a messager: Matrix, Berty, Jami, Status
            if ip not in _list_status_ips_: continue

            ipinfo_file_path = os.path.join(ipinfo_data_dir, file_name)
            try:
                ipinfo_analyzer.analyzer(ipinfo_file_path)
            except Exception as e:
                print(e, end=' ')
                print(ipinfo_file_path)

    ipinfo_analyzer.print_info()
    # ***********************************
    # step03: load ipapi data we detected
    # ***********************************
    ipapi_data_dir = r'\DecentralizedMessagers\DataNeedToAnalysis\ip-api-response'
    isp_list = []
    for file_name in os.listdir(ipapi_data_dir):
        if file_name.endswith('.json'):
            ip = file_name[:-5]
            if ip not in _list_status_ips_: continue

            ipapi_data_path = os.path.join(ipapi_data_dir, file_name)
            with open(ipapi_data_path, 'r', encoding='utf-8') as f:
                content = f.read()
                try:
                    ipapi_response = json.loads(content)
                    ipapi_response_keys = list(ipapi_response.keys())
                    if 'isp' in ipapi_response_keys:
                        isp = ipapi_response['isp']
                        isp_list.append(isp)
                except AttributeError:
                    ipapi_response = ipapi_response[0]
                    ipapi_response_keys = list(ipapi_response.keys())
                    if 'isp' in ipapi_response_keys:
                        isp = ipapi_response['isp']
                        isp_list.append(isp)
                except JSONDecodeError:
                    print(JSONDecodeError, file_name)
                    print(content)
                    matches = re.findall(r'\[.*?\]', content, re.DOTALL)
                    print(matches)
    print()
    print("ISP: ", len(Counter(isp_list)), Counter(isp_list).most_common(10))
