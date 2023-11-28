#NSX Label Set Application
#For development - Findout if groups have duplicated VMs so client can decide which one to use
#For development - Add an option to ask for confirmation when workload already has tags

import requests,json,getpass,pce_ld
requests.packages.urllib3.disable_warnings()

host = ''

def nlogin_error_handling():
    try: nbase_url
    except NameError:
        print('***************************************************************')
        print('Enter NSX login information before proceeding')
        print('***************************************************************')
        nsx_connect()


def save_login():
   data = {}
   data['nusername'] = nusername
   data['nserver'] = nserver
   data['vusername'] = vusername
   data['vserver'] = vserver
   with open('nsx_login.json','w') as f:
       json.dump(data, f)
def ll():
    load_login()


def load_login():
    global host
    host = {}
    with open('nsx_login.json','r') as f:
        host = json.load(f)

def nsx_connect():
    global nusername,npassword,nserver,nbase_url
    if host != '':
        print('Login from loaded file')
        print('NSX Username: ' + host['nusername'])
        print('NSX Manager Host: ' + host['nserver'])
        nusername = host['nusername']
        nserver = host['nserver']
        npassword =  getpass.getpass('Password : ')
    else:
        nusername =  input('Username : ')
        npassword =  getpass.getpass('Password : ')
        nserver =  input('NSX Manager fqdn:port : ')
    nbase_url = 'https://' + nserver
    

def vc_connect():
    global vserver,vbase_url,token,vusername
    if host != '':
        print('Login from loaded file')
        print('VCenter Username: ' + host['vusername'])
        print('VCenter Host: ' + host['vserver'])
        vusername = host['vusername']
        vserver = host['vserver']
        vpassword =  getpass.getpass('Password : ')
    else:
        vserver =  input('VCenter Manager fqdn:port : ')
        vusername =  input('Username : ')
        vpassword =  getpass.getpass('Password : ')
        
        
    vbase_url = 'https://' + vserver
    auth_url = vbase_url + '/rest/com/vmware/cis/session'
    a = requests.auth.HTTPBasicAuth(vusername,vpassword)
    r = requests.post(auth_url,auth=a,verify=False)
    js = json.loads(r.text)
    token = 'vmware-api-session-id=' + js['value']


def get_sec_group():
    nlogin_error_handling()
    url = nbase_url + '/api/2.0/services/securitygroup/scope/globalroot-0/'
    headers = {'Accept' : 'application/json'}
    a = requests.auth.HTTPBasicAuth(nusername,npassword)
    r = requests.get(url,headers=headers,auth=a,verify=False)
    sec_groups = json.loads(r.text)
    return(sec_groups)


def get_vm_hostname(vm):
    try: token
    except NameError:
            vc_connect()
    headers = {'Accept' : 'application/json'}
    headers['Cookie'] = token
    url = vbase_url + '/rest/vcenter/vm/' + vm + '/guest/identity'
    r = requests.get(url,headers=headers,verify=False)
    js = json.loads(r.text)
    if 'value' in js:
        if 'host_name' in js['value']:
            hostname = js['value']['host_name']
        else:
            hostname = 'VM Tools not installed'
    return(hostname)


def get_sec_group_vms(g):
    groups = get_sec_group()
    for i in groups:
        if i['name'] == g:
            obj_id = i['objectId']
            
    url = nbase_url + '/api/2.0/services/securitygroup/' + obj_id + '/translation/virtualmachines'
    headers = {'Accept' : 'application/json'}
    a = requests.auth.HTTPBasicAuth(nusername,npassword)
    r = requests.get(url,headers=headers,auth=a,verify=False)
    js = json.loads(r.text)
    return(js)


def get_sec_group_vm_hostname(g):
    vms = get_sec_group_vms(g)
    vm_name_hostname = []
    for i in vms['vmNodes']:
        hostname = get_vm_hostname(i['vmId'])
        i['hostname'] = hostname
        vm_name_hostname.append(i)
    return(vm_name_hostname)


def get_sec_group_names():
    g = get_sec_group()
    sec_group_names = []
    for i in g:
        sec_group_names.append(i['name'])
    return(sec_group_names)


def show_sec_groups():
    s = get_sec_group_names()
    for i in s:
        print(i)


def show_sec_group_vms():
    g = get_sec_group_names()
    print('')
    for i in g:
        print(g.index(i),' ',i)
    s = int(input('\n Select the security group to show associated VMs: '))
    group = g[s]
    g = get_sec_group_vm_hostname(group)
    print('')
    print('The VMs below are part of the Security Group: ' + group)
    print('')
    print("{:<60} {:<10}".format('VM Name','Hostname'))
    for i in g:
        print("{:<60} {:<10}".format(i['vmName'],i['hostname']))


def select_labels():
    li = pce_ld.labels()
    labels = []
    print('Hit "Enter" to leave label blank')
    rlname = input('Enter Role label: ')
    alname = input('Enter App label: ')
    elname = input('Enter Environment label: ')
    llname = input('Enter Location label: ')
    if rlname in li:
        labels.append({'href': li[rlname]})
    if alname in li:
        labels.append({'href': li[alname]})
    if elname in li:
        labels.append({'href': li[elname]})
    if llname in li:
        labels.append({'href': li[llname]})
    return(labels)
    

def match_workloads():
    g = get_sec_group_names()
    print('')
    for i in g:
        print(g.index(i),' ',i)
    s = int(input('\n Select the security group to be associated with PCE labels: '))
    group = g[s]
    g = get_sec_group_vm_hostname(group)
    hostnames = []
    nf = []
    for i in g:
        if i['hostname'] != 'VM Tools not installed':
            fqdn = i['hostname']
            sn = fqdn.split('.')[0]
            hostnames.append(sn)
        else:
            nf.append('Could not fetch hostname for vm: ' + i['vmName'])
    #li = pce_ld.labels()
    wi, wl = pce_ld.workloads()
    workloads = []
    for i in wi:
        if i in hostnames:
            workloads.append(wi[i])
    for i in hostnames:
        if i not in wi:
            nf.append('No matching workload for VM: ' + i)
    print('')
    for i in nf:
        print(i)
    return(workloads)


def apply_labels():
    workloads = match_workloads()
    labels = select_labels()
    for i in workloads:
        url = pce_ld.base_url + i
        a = pce_ld.auth_creds
        data = {'labels':labels}
        js = json.dumps(data)
        h = {'Content-type': 'application/json'}
        r = requests.put(url,data=js,headers=h,auth=a,verify=False)
        if r.status_code not in [200,201,202,204]:
            print(r.text)


def help():
    print('help() -> displays this menu')
    print('apply_labels() -> Asks for Security Group selection and labels.')
    print('                  Workloads in the security group receive entered labels.')
    print('show_sec_groups() -> Shows NSX security groups')
    print('show_sec_group_vms() -> Shows the VMs that are part of an NSX security group')
    print('save_login() -> saves the nsx and vcenter login and server info, except password')
    print('load_login() -> loads nsx and vcenter login and server info, except password')
