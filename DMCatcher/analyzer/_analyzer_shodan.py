# coding=utf-8
__author__ = 'lihao'

from json import JSONDecodeError
from itertools import combinations
import pandas as pd
import json
import logging
import collections
from collections import Counter
import os

import re

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a')

cves_file_dir = r'\DecentralizedMessagers\DataNeedToAnalysis\cve.circl.lu-response'

class ShodanAnalyzer(object):
    def __init__(self):
        self.opened_ports = list()
        self.belong_tags = list()
        self.domains = list()
        self.hostnames = list()
        self.products = list()

        self.ssh_cipher_method = []
        self.ssh_server_host_key_algorithms = []
        self.ssh_encryption_algorithms = []
        self.ssh_kex_algorithms = []
        self.ssh_mac_algorithms = []

        self.ssl_sig_alg = []
        self.cloud_provider = []
        self.vulns = []

        self.continent_homeserver_ips = collections.defaultdict(list)

    def analyzer(self, file_path):
        self.shodan_response_file = file_path

        with open(self.shodan_response_file, 'r', encoding='utf-8') as f:
            shodan_response = json.load(f)
            shodan_response_keys = list(shodan_response.keys())

            ip = shodan_response['ip_str']
            org = shodan_response['org']
            opened_ports = shodan_response['ports']
            self.opened_ports.extend(opened_ports)
            tags = shodan_response['tags']
            if len(tags) > 0:
                self.belong_tags.extend(tags)
            domains = shodan_response['domains']
            if len(domains) > 0:
                self.domains.extend(domains)
            hostnames = shodan_response['hostnames']
            if len(hostnames) > 0:
                self.hostnames.extend(hostnames)
            if 'vulns' in shodan_response.keys():
                vulns = shodan_response['vulns']
                self.vulns.extend(vulns)
                if 'CVE-2023-44487' in vulns:
                    pass

            data = shodan_response['data']
            for idx, item in enumerate(data):
                shodan_response_data_keys = list(item.keys())
                # print(shodan_response_data_keys)
                if 'product' in shodan_response_data_keys:
                    product = item['product']
                    self.products.append(product)
                if 'http' in shodan_response_data_keys:
                    http = item['http']
                if 'cpe' in shodan_response_data_keys:
                    cpe = item['cpe']
                if 'ssh' in shodan_response_data_keys:
                    ssh = item['ssh']
                    cipher_method = ssh['cipher']
                    mac_method = ssh['mac']
                    fingerprint = ssh['fingerprint']
                    server_host_key_algorithms = ssh['kex']['server_host_key_algorithms']
                    encryption_algorithms = ssh['kex']['encryption_algorithms']
                    self.ssh_encryption_algorithms.extend(encryption_algorithms)
                    kex_algorithms = ssh['kex']['kex_algorithms']
                    compression_algorithms = ssh['kex']['compression_algorithms']
                    mac_algorithms = ssh['kex']['mac_algorithms']
                    self.ssh_mac_algorithms.extend(mac_algorithms)
                if 'ssl' in shodan_response_data_keys:
                    ssl = item['ssl']
                    versions = ssl['versions']
                    cert = ssl['cert']
                    sig_alg = cert['sig_alg']
                    self.ssl_sig_alg.append(sig_alg)
                    pubkey = cert['pubkey']
                    handshake_states = ssl['handshake_states']
                # if 'data' in shodan_response_data_keys:
                #     data = item['data']
                if 'cloud' in shodan_response_data_keys:
                    cloud = item['cloud']
                    provider = cloud['provider']
                    self.cloud_provider.append(provider)

    def cve_analyzer(self):
        print("Vulns: ", len(Counter(self.vulns)), Counter(self.vulns).most_common(10))
        top_vulns_list = [vuln for vuln, count in Counter(self.vulns).most_common(10)]
        for file_name in os.listdir(cves_file_dir):
            if file_name.endswith('.json'):
                cve_name = file_name.split('.json')[0]
                if cve_name in top_vulns_list:
                    print(cve_name)

                with open(os.path.join(cves_file_dir, file_name), 'r', encoding='utf-8') as f:
                    cve_data_dict = json.load(f)
                    cveMetadata = cve_data_dict['cveMetadata']
                    containers = cve_data_dict['containers']
                    containers_adp = containers['adp']
                    containers_cna = containers['cna']
                    cna_keys = list(containers_cna.keys())
                    # print(cna_keys)
                    descriptions = containers_cna['descriptions']
                    affected = containers_cna['affected']
                    for affect_item in affected:
                        # print(affect_item.keys())
                        if 'vendor' in affect_item.keys():
                            affected_vendor = affect_item['vendor']
                        if 'product' in affect_item.keys():
                            affected_product = affect_item['product']
                        if 'defaultStatus' in affect_item.keys():
                            defaultStatus = affect_item['defaultStatus']
                        if 'packageName' in affect_item.keys():
                            packageName = affect_item['packageName']
                    providerMetadata = containers_cna['providerMetadata']
                    # print(providerMetadata)
                    if 'problemTypes' in cna_keys:
                        problemTypes = containers_cna['problemTypes']
                        for problemType in problemTypes:
                            for description in problemType['descriptions']:
                                if 'cweId' in description.keys():
                                    cweId = description['cweId']
                                    cwe_description = description['description']
                                    # print(cweId, cwe_description)
                    if 'metrics' in cna_keys:
                        metrics = containers_cna['metrics']
                        for item in metrics:
                            if 'cvssV3_1' in item.keys():
                                cvssV3_1 = item['cvssV3_1']
                    if 'workarounds' in cna_keys:
                        workarounds = containers_cna['workarounds']
                    if 'x_legacyV4Record' in cna_keys:
                        x_legacyV4Record = containers_cna['x_legacyV4Record']
                        CVE_data_meta = x_legacyV4Record['CVE_data_meta']
                        ASSIGNER = CVE_data_meta['ASSIGNER']

    def print_info(self):
        print("Opened ports: ", len(Counter(self.opened_ports)), Counter(self.opened_ports).most_common(10))
        print("Belonging tags: ", len(Counter(self.belong_tags)), Counter(self.belong_tags).most_common(10))
        print("Domains: ", len(Counter(self.domains)), Counter(self.domains).most_common(10))
        print("Hostnames: ", len(Counter(self.hostnames)), Counter(self.hostnames).most_common(10))
        print("Products: ", len(Counter(self.products)), Counter(self.products).most_common(10))
        print()
        print("ssh_mac_algorithms: ", len(Counter(self.ssh_mac_algorithms)), Counter(self.ssh_mac_algorithms).most_common(10))
        print("ssh_encryption_algorithms: ", len(Counter(self.ssh_encryption_algorithms)), Counter(self.ssh_encryption_algorithms).most_common(10))
        print("ssl_sig_alg: ", len(Counter(self.ssl_sig_alg)), Counter(self.ssl_sig_alg).most_common(10))
        print("cloud_provider: ", len(Counter(self.cloud_provider)), Counter(self.cloud_provider).most_common(10))
        print()
        self.cve_analyzer()
        print()


if __name__ == '__main__':
    # *********************************
    # step01: load ip data we collected
    # *********************************
    ip_data_dir = r'./ip_data'
    _list_berty_ips_ = list(
        pd.read_csv(os.path.join(ip_data_dir, r'berty-ips-2025-04-04.csv'), header=None).to_numpy()[:, -1])
    _list_jami_ips_ = list(
        pd.read_csv(os.path.join(ip_data_dir, r'jami-ips-2025-04-12.csv'), header=None).to_numpy()[:, -1])
    _list_matrix_ips_ = list(
        pd.read_csv(os.path.join(ip_data_dir, r'matrix-ips-2025-03-28.csv'), header=None).to_numpy()[:, -1])
    _list_status_ips_ = list(
        pd.read_csv(os.path.join(ip_data_dir, r'status-ips-2025-04-13.csv'), header=None).to_numpy()[:, -1])
    # *******************************
    # step02: load shodan we detected
    # *******************************
    shodan_data_dir = r'\DecentralizedMessagers\DataNeedToAnalysis\shodan_host_response'
    shodan_analyzer = ShodanAnalyzer()
    for file_name in os.listdir(shodan_data_dir):
        if file_name.endswith('.json'):
            ip = file_name[:-5]
            # select a messager: Matrix, Berty, Jami, Status
            if ip not in _list_status_ips_: continue

            shodan_file_path = os.path.join(shodan_data_dir, file_name)
            try:
                shodan_analyzer.analyzer(shodan_file_path)
            except Exception as e:
                print(e, end=' ')
                print(shodan_file_path)
    shodan_analyzer.print_info()
