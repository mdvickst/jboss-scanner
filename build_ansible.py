#!/usr/bin/env python

import sys
from collections import defaultdict
import pexpect
import re
import os
import csv

eap_classifications = {
    'JBoss_4_0_0': 'JBossAS-4',
    'JBoss_4_0_1_SP1': 'JBossAS-4',
    'JBoss_4_0_2': 'JBossAS-4',
    'JBoss_4_0_3_SP1': 'JBossAS-4',
    'JBoss_4_0_4_GA': 'JBossAS-4',
    'Branch_4_0': 'JBossAS-4',
    'JBoss_4_2_0_GA': 'JBossAS-4',
    'JBoss_4_2_1_GA': 'JBossAS-4',
    'JBoss_4_2_2_GA': 'JBossAS-4',
    'JBoss_4_2_3_GA': 'JBossAS-4',
    'JBoss_5_0_0_GA': 'JBossAS-5',
    'JBoss_5_0_1_GA': 'JBossAS-5',
    'JBoss_5_1_0_GA': 'JBossAS-5',
    'JBoss_6.0.0.Final': 'JBossAS-6',
    'JBoss_6.1.0.Final': 'JBossAS-6',
    '1.0.1.GA': 'JBossAS-7',
    '1.0.2.GA': 'JBossAS-7',
    '1.1.1.GA': 'JBossAS-7',
    '1.2.0.CR1': 'JBossAS-7',
    '1.2.0.Final': 'WildFly-8',
    '1.2.2.Final': 'WildFly-8',
    '1.2.4.Final': 'WildFly-8',
    '1.3.0.Beta3': 'WildFly-8',
    '1.3.0.Final': 'WildFly-8',
    '1.3.3.Final': 'WildFly-8',
    '1.3.4.Final': 'WildFly-9',
    '1.4.2.Final': 'WildFly-9',
    '1.4.3.Final': 'WildFly-9',
    #'1.4.3.Final': 'WildFly-10',
    '1.4.4.Final': 'WildFly-10',
    '1.5.0.Final': 'WildFly-10',
    '1.5.1.Final': 'WildFly-10',
    '1.5.2.Final': 'WildFly-10',
    'JBPAPP_4_2_0_GA': 'EAP-4.2',
    'JBPAPP_4_2_0_GA_C': 'EAP-4.2',
    'JBPAPP_4_3_0_GA': 'EAP-4.3',
    'JBPAPP_4_3_0_GA_C': 'EAP-4.3',
    'JBPAPP_5_0_0_GA': 'EAP-5.0.0',
    'JBPAPP_5_0_1': 'EAP-5.0.1',
    'JBPAPP_5_1_0': 'EAP-5.1.0',
    'JBPAPP_5_1_1': 'EAP-5.1.1',
    'JBPAPP_5_1_2': 'EAP-5.1.2',
    'JBPAPP_5_2_0': 'EAP-5.2.0',
    '1.1.2.GA-redhat-1': 'EAP-6.0.0',
    '1.1.3.GA-redhat-1': 'EAP-6.0.1',
    '1.2.0.Final-redhat-1': 'EAP-6.1.0',
    '1.2.2.Final-redhat-1': 'EAP-6.1.1',
    '1.3.0.Final-redhat-2': 'EAP-6.2',
    #'1.3.3.Final-redhat-1': 'EAP-6.2',
    '1.3.3.Final-redhat-1': 'EAP-6.3',
    '1.3.4.Final-redhat-1': 'EAP-6.3',
    '1.3.5.Final-redhat-1': 'EAP-6.3',
    '1.3.6.Final-redhat-1': 'EAP-6.4',
    '1.3.7.Final-redhat-1': 'EAP-6.4',
    '1.4.4.Final-redhat-1': 'EAP-7.0',
    '1.5.1.Final-redhat-1': 'EAP-7.0'
}

brms_classifications = {
    '6.4.0.Final-redhat-3': 'BRMS 6.3.0',
    '6.3.0.Final-redhat-5': 'BRMS 6.2.0',
    '6.2.0.Final-redhat-4': 'BRMS 6.1.0',
    '6.0.3-redhat-6': 'BRMS 6.0.3',
    '6.0.3-redhat-4': 'BRMS 6.0.2',
    '6.0.2-redhat-6': 'BRMS 6.0.1',
    '6.0.2-redhat-2': 'BRMS 6.0.0',
    '5.3.1.BRMS': 'BRMS 5.3.1',
    '5.3.0.BRMS': 'BRMS 5.3.0',
    '5.2.0.BRMS': 'BRMS 5.2.0',
    '5.1.0.BRMS': 'BRMS 5.1.0',
    '5.0.2.BRMS': 'BRMS 5.0.2',
    '5.0.1.BRMS': 'BRMS 5.0.1',
    'drools-core-5.0.0': 'BRMS 5.0.0',
    '6.5.0.Final': 'Drools 6.5.0'
}

fuse_classifications = {
    'redhat-630187': 'Fuse-6.3.0',
    'redhat-621084': 'Fuse-6.2.1',
    'redhat-620133': 'Fuse-6.2.0',
    'redhat-611412': 'Fuse-6.1.1',
    'redhat-610379': 'Fuse-6.1.0',
    'redhat-60024': 'Fuse-6.0.0',
}

columns = ['IP Address', 'hostname', 'cpu_cores', 'installed_versions', 'running_versions', 'deploy_dates', 'date.yum_history', 'date.filesystem_create', 'date.machine_id', 'date.anaconda_log', 'brms.kie-war-ver', 'brms.kie-api-ver', 'brms.drools-core-ver', 'cxf-ver', 'activemq-ver', 'camel-ver']


def encrypt(filename, vault_pass):
    result = None

    try:
        child = pexpect.spawn('ansible-vault encrypt ' + filename)
        result = child.expect('Vault password:')
        child.sendline(vault_pass)
        result = child.expect(['Encryption successful', 'ERROR! input is already encrypted', pexpect.EOF, 'Confirm New Vault password:'])
        if result == 3:
            child.sendline(vault_pass)
            result = child.expect(['Encryption successful', 'ERROR! input is already encrypted', pexpect.EOF])
        return result  # 0 or 2 means successful, 1 means already encrypted
    except pexpect.EOF:
        print('pexpect unexpected EOF')
        return -1
    except pexpect.TIMEOUT:
        print('pexpect timed out')
        return -1


def run_ansible_with_vault(cmd_string, vault_pass, ssh_key_passphrase = None):
    result = None
    try:
        child = pexpect.spawn(cmd_string, timeout=None)
        result = child.expect('Vault password:')
        child.sendline(vault_pass)
        child.logfile = sys.stdout
        i = child.expect([pexpect.EOF, 'Enter passphrase for key .*:'])
        if i == 1:
            child.logfile = None
            child.sendline(ssh_key_passphrase)
            child.logfile = sys.stdout
            child.expect(pexpect.EOF)
        return child.before
    except pexpect.EOF:
        print(str(result))
        print('pexpect unexpected EOF')
    except pexpect.TIMEOUT:
        print(str(result))
        print('pexpect timed out')


class AnsibleCore(object):
    def __init__(self):
        self.success_auths = dict()
        self.auth_map = defaultdict(list)
        self.mapped_hosts = set()

    def prepareScan(self):
        self.success_auths = dict()
        self.auth_map = defaultdict(list)
        self.mapped_hosts = set()

    def build_ping_inventory(self, auth, host_list, encryption_password, scan_type, win_enabled=False):
        if not win_enabled or scan_type == 'rhel':
            inventory_string = "[all]\n" + host_list + "\n"
            inventory_string += "[all:vars]\n"

            inventory_string += "ansible_ssh_user=" + auth.username + "\n"
            if auth.type == "ssh_key":
                inventory_string += "ansible_ssh_private_key_file=" + auth.path + "\n"
            elif auth.type == "ssh":
                inventory_string += "ansible_ssh_pass=" + auth.password + "\n"
            else:
                # auth type not recognized
                return False
        else:
            inventory_string = "[windows]\n" + host_list + "\n"
            inventory_string += "[windows:vars]\n"
            inventory_string += "ansible_user=" + auth.username + "\n"
            inventory_string += "ansible_password=" + auth.password + "\n"
            inventory_string += "ansible_port=5986\n"
            inventory_string += "ansible_connection=winrm\n"
            inventory_string += "ansible_winrm_server_cert_validation=ignore\n"

        f = open('/tmp/ping-inventory', 'w')
        f.write(inventory_string)
        f.close()
        result = encrypt('/tmp/ping-inventory', encryption_password)
        if result == -1:
            os.remove('/tmp/ping-inventory')
            print 'Error encrypting ping-inventory file, could not continue'
            exit(1)

    def build_master_inventory(self, encryption_password, scan_type, win_enabled=False):

        if not win_enabled or scan_type == 'rhel':
            inventory_string = "[all]\n"
        else:
            inventory_string = "[windows]\n"

        for auth_name in self.auth_map.keys():
            auth = self.success_auths[auth_name]
            for host in self.auth_map[auth_name]:
                if not win_enabled or scan_type == 'rhel':
                    inventory_string += host + ' ansible_ssh_host=' \
                                        + host + " ansible_ssh_user=" \
                                        + auth.username
                    if auth.type == "ssh":
                        inventory_string += ' ansible_ssh_pass=' + auth.password
                    elif auth.type == 'ssh_key':
                        inventory_string += " ansible_ssh_private_key" \
                                            "_file=" + auth.path
                else:
                    inventory_string += host + " ansible_user=" + auth.username \
                                        + " ansible_password=" + auth.password
                inventory_string += '\n'

        if win_enabled:
            inventory_string += '\n'
            inventory_string += "[windows:vars]\n"
            inventory_string += "ansible_port=5986\n"
            inventory_string += "ansible_connection=winrm\n"
            inventory_string += "ansible_winrm_server_cert_validation=ignore\n"

        f = open('/tmp/master-inventory', 'w')
        f.write(inventory_string)
        f.close()
        result = encrypt('/tmp/master-inventory', encryption_password)
        if result == -1:
            os.remove('/tmp/master-inventory')
            print 'Error encrypting master-inventory file, could not continue'
            exit(1)

    def run_ping_scan(self, auth, encryption_password, forks=50, scan_type='rhel', win_enabled=False):
        if not win_enabled or scan_type == 'rhel':
            cmd_string = 'ansible all -m' \
                         ' ping  -i /tmp/ping-inventory -f ' + str(forks)
        else:
            cmd_string = 'ansible all -m' \
                         ' win_ping  -i /tmp/ping-inventory -f ' + str(forks)
        cmd_string += ' --ask-vault-pass'
        if auth.type == "ssh_key" and auth.password is not None:
            out = run_ansible_with_vault(cmd_string, encryption_password, auth.password)
        else:
            out = run_ansible_with_vault(cmd_string, encryption_password)

        with open(auth.name + '-ping_log', 'w') as f:
            f.write(out)

        out = out.split('\n')
        last_ip = ''
        for l in range(len(out)):
            pattern = re.compile("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*=> {")
            match = pattern.search(out[l])
            if match is not None:
                match2 = re.search("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", out[l])
                if match2:
                    last_ip = match2.group(0)
            host_line = ''
            if 'pong' in out[l] or 'msg' in out[l] and 'Failed to connect' not in out[l] \
                                and 'Authentication failure' not in out[l] \
                                and 'Failed to establish a new connection' not in out[l] \
                                and 'the specified credentials were rejected by the server' not in out[l] \
                                and last_ip != '':
                if auth.name not in self.success_auths:
                    self.success_auths[auth.name] = auth
                host_ip = last_ip
                last_ip = ''
                #host_ip = re.sub('(.*0;3.m)', '', host_ip)
                if host_ip not in self.mapped_hosts:
                    self.auth_map[auth.name].append(host_ip)
                    self.mapped_hosts.add(host_ip)

    def run_scan(self, encryption_password, scan_type='rhel', win_enabled=False, forks=50):
        results = {}
        cmd_string = 'ansible-playbook rho_playbook.yml -i /tmp/master-inventory -v -f ' + str(forks) \
                   + ' --extra-vars "type=' + scan_type + ' win_enabled=' + str(win_enabled) + '" --ask-vault-pass'
        out = run_ansible_with_vault(cmd_string, encryption_password)

        for line in out.split('\n'):
            if 'Gather jboss-modules.jar versions' in line or 'Gather run.jar versions' in line:
                key = 'installed_versions'
            elif 'Gather jboss versions currently running' in line:
                key = 'running_versions'
            elif 'Gather hostname' in line:
                key = 'hostname'
            elif 'Gather cpu cores' in line:
                key = 'cpu_cores'
            elif 'Gather date.anaconda_log' in line:
                key = 'date.anaconda_log'
            elif 'Gather date.machine_id' in line:
                key = 'date.machine_id'
            elif 'Gather date.filesystem_create' in line:
                key = 'date.filesystem_create'
            elif 'Gather date.yum_history' in line:
                key = 'date.yum_history'
            elif 'Gather brms.kie-api-ver' in line:
                key = 'brms.kie-api-ver'
            elif 'Gather brms.drools-core-ver' in line:
                key = 'brms.drools-core-ver'
            elif 'Gather brms.kie-war-ver' in line:
                key = 'brms.kie-war-ver'
            elif 'Gather brms.business-central-war-ver' in line:
                key = 'brms.business-central-war-ver'
            elif 'Gather activemq-ver' in line:
                key = 'activemq-ver'
            elif 'Gather camel-ver' in line:
                key = 'camel-ver'
            elif 'Gather cxf-ver' in line:
                key = 'cxf-ver'
            elif 'ok:' in line or 'changed:' in line or 'fatal:' in line:
                match = re.search("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", line)
                if match:
                    ip = match.group(0)
                    if ip not in results:
                        results[ip] = {}
                    match = re.search('(stdout":\s")(.*)(\\\\?r?\\\\?n?", "stdout_lines)', line)
                    if match:
                        if key == 'installed_versions' :
                            jboss_releases = []
                            deploy_dates = []
                            versions = match.group(2).replace('\\r\\n', '').split('; ')
                            for v in versions:
                                if v is not '' and key == 'installed_versions':
                                    ver = v.replace('\\r\\n', '').split('**')[0]
                                    deploy_date = v.replace('\\r\\n', '').split('**')[1]
                                    deploy_dates.append(deploy_date)
                                    if ver in eap_classifications:
                                        jboss_releases.append(eap_classifications[ver])
                                    elif ver.strip() != '':
                                        jboss_releases.append('Unknown-Release: ' + ver)
                                elif v is not '':
                                    if v in brms_classifications:
                                        jboss_releases.append(brms_classifications[v])
                                    elif v.strip() != '':
                                        jboss_releases.append('Unknown-Release: ' + v)
                            if key not in results[ip] or results[ip][key] == '':
                                results[ip][key] = "; ".join(jboss_releases)
                                if key == 'installed_versions':
                                    results[ip]['deploy_dates'] = "; ".join(deploy_dates)
                            else:
                                results[ip][key] += "; " + "; ".join(jboss_releases)
                                if key == 'installed_versions':
                                    results[ip]['deploy_dates'] += "; " + "; ".join(deploy_dates)
                        elif key == 'brms.kie-api-ver' or key == 'brms.drools-core-ver' or key == 'brms.kie-war-ver':
                            brms_releases = []
                            versions = match.group(2).replace('\\r\\n', ';').split(';')
                            for v in versions:
                                if v is not '':
                                    if v in brms_classifications:
                                        brms_releases.append(brms_classifications[v])
                                    elif v.strip() != '':
                                        brms_releases.append('Unknown-Release: ' + v)
                            if key not in results[ip] or results[ip][key] == '':
                                results[ip][key] = "; ".join(brms_releases)
                            else:
                                results[ip][key] += "; " + "; ".join(brms_releases)
                        elif key == 'activemq-ver' or key == 'camel-ver' or key == 'cxf-ver':
                            fuse_releases = []
                            versions = match.group(2).replace('\\r\\n', ';').split(';')
                            for v in versions:
                                if v is not '':
                                    if v in fuse_classifications:
                                        fuse_releases.append(fuse_classifications[v])
                                    elif v.strip() != '':
                                        fuse_releases.append('Unknown-Release: ' + v)
                            if key not in results[ip] or results[ip][key] == '':
                                results[ip][key] = "; ".join(fuse_releases)
                            else:
                                results[ip][key] += "; " + "; ".join(fuse_releases)
                        elif key == 'running_versions':
                            results[ip][key] = match.group(2).replace('\\r\\n', ';')
                        else:
                            results[ip][key] = match.group(2).replace('\\r\\n', '')
        f_path = 'jboss_scan_results.csv'
        f = open(f_path, "w")
        first_pass = True
        for ip in results.keys():
            writer = csv.writer(f, delimiter=',')
            if first_pass:
                writer.writerow(columns)
                first_pass = False

            values = []

            for key in columns:
                if key == 'IP Address':
                    values.append(str(ip))
                elif key in results[ip]:
                    if type(results[ip][key]) is str:
                        values.append(results[ip][key].replace('\r\n', ''))
                    else:
                        values.append(results[ip][key])
                else:
                    values.append('')

        f.close()
