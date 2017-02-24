import csv
import ast
import os
import json
from ansible.module_utils.basic import AnsibleModule


classifications = {
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
    #'1.4.3.Final': 'WildFly-9',
    '1.4.3.Final': 'WildFly-10',
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

class Results(object):
    # The class Results contains the functionality
    # to parse data passed in from the playbook
    # and to output it in the csv format in the
    # file path specified.

    def __init__(self, module):
        self.module = module
        self.name = module.params['name']
        self.file_path = module.params['file_path']
        self.vals = module.params['vals']

    def write_to_csv(self):
        f_path = self.file_path
        f = open(f_path, "w")
        file_size = os.path.getsize(f_path)
        vals = ast.literal_eval(self.vals)
        fields = vals[0].keys()
        fields.sort()
        writer = csv.writer(f, delimiter=',')
        if file_size == 0:
            writer.writerow(fields)
        for d in vals:
            sorted_keys = d.keys()
            sorted_keys.sort()
            sorted_values = []
            for k in sorted_keys:
                if k == "installed_versions":
                    jboss_releases = []
                    versions = d[k].replace('\r\n', '').split('; ')
                    for v in versions:
                        if v in classifications:
                            jboss_releases.append(classifications[v])
                        elif v.strip() != '':
                            jboss_releases.append('Unknown-JBoss-Release: ' + v)
                    sorted_values.append("; ".join(jboss_releases))
                else:
                    if type(d[k]) is str:
                        sorted_values.append(d[k].replace('\r\n', ''))
                    else:
                        sorted_values.append(d[k])
            writer.writerow(sorted_values)


def main():
    module = AnsibleModule(argument_spec=dict(name=dict(required=True),
                                              file_path=dict(required=True),
                                              vals=dict(required=True)))
    results = Results(module=module)
    results.write_to_csv()
    vals = json.dumps(results.vals)
    module.exit_json(changed=False, meta=vals)

if __name__ == '__main__':
    main()
