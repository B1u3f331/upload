from flask import request, Blueprint
from smb.SMBConnection import SMBConnection
import glob 
import socket
import os
import fs.smbfs
from fs.subfs import ClosingSubFS
from fs.ftpfs import FTPFS
import ipaddress
from hackbot.Api import Api as Api_Hackbot
from threading import Thread
from config import CONFIG

keyword = CONFIG['sensitive_files']['keyword']
hidden = CONFIG['sensitive_files']['include_hidden_smb']
HACKBOT_BASE_URL = CONFIG['hackbot']['base_url']
HACKBOT_USERNAME = CONFIG['hackbot']['username']
HACKBOT_PASSWORD = CONFIG['hackbot']['password']

sensitive_api = Blueprint('sensitive-files', __name__)

@sensitive_api.route('/scans', methods=['POST'])
def scans():
    req_data = request.get_json()
    req_tuple = req_data.items()
    Thread(target=process_scan, args=(req_tuple,)).start()
    return {'message': 'Scan in progress'}, 200

def process_scan(req_tuple):
    target_result = {}
    req_data = dict(req_tuple)
    target_result['name'] = req_data['name']
    target_result['targets'] = []
    targets = req_data['targets'] if 'targets' in req_data else []
    arr_target = []
    for target in targets:
        sensitive_files_result = []
        '''
        ==========================
        |          ftp           |
        ==========================
        '''
        host = target['target']
        arr_sensitive = []
        if target['scanningToolOptions']['ftp']['enabled'] != False:
            store_dir = []
            store = []
            try:
                root_ftp = target['scanningToolOptions']['ftp']
                username_ftp = root_ftp['username'] if 'username' in root_ftp else 'anonymous'
                password_ftp = root_ftp['password'] if 'password' in root_ftp else ''
                account_ftp = ''
                timeout_ftp = 10
                port_ftp = int(root_ftp['port']) if 'port' in root_ftp else 21
                proxy_ftp = root_ftp['proxy'] if 'proxy' in root_ftp else None
                tls_ftp = root_ftp['tls'] if 'tls' in root_ftp else False

                home_fs = FTPFS(host=host, user=username_ftp, passwd=password_ftp, acct=account_ftp, timeout=timeout_ftp, port=port_ftp, proxy=proxy_ftp) #tls=tls_ftp

                store_dir = home_fs.listdir('.')

                for match in home_fs.glob("**/*"):
                    temp = match.path
                    if any(x in match.path.lower() for x in list(keyword.split(","))):
                        store.append(temp)
                
                store_arr = []
                for res in store:
                    store_arr.append({'protocol': 'ftp', 'path': res})

                for x in store_arr:
                    arr_sensitive.append(x)

            except Exception as e:
                print(e)
                

        '''
        ==========================
        |          smb           |
        ==========================
        '''
        if target['scanningToolOptions']['smb']['enabled'] != False:
            store_share = []
            store_path = []
            try:
                root_smb = target['scanningToolOptions']['smb']
                username_smb = root_smb['username'] if 'username' in root_smb else ''
                password_smb = root_smb['password'] if 'password' in root_smb else ''
                domain_smb = root_smb['domain'] if 'domain' in root_smb else ''
                port_smb = int(root_smb['port']) if 'port' in root_smb else 445
                nameport_smb = int(root_smb['namePort']) if 'namePort' in root_smb else 137
                directtcp_smb = True

                try:
                    ipaddress.ip_address(host)
                    ip_address_smb = host
                except:
                    try:
                        ip_address_smb = socket.gethostbyname(host)
                    except:
                        ip_address_smb = host

                conn = SMBConnection(username_smb, password_smb, '', ip_address_smb, domain=domain_smb, is_direct_tcp=directtcp_smb)
                assert conn.connect(ip_address_smb, port_smb)
                filelist = conn.listShares()

                if hidden == 'true':
                    for share in filelist:
                        store_share.append(share.name)

                else:
                    for share in filelist:
                        if share.name[-1] != '$':
                            store_share.append(share.name)
                
                
                
                
                
#                 for share in store_share:
#                     try:
#                         smb_fs = fs.smbfs.SMBFS(host=(ip_address_smb,ip_address_smb), username=username_smb, passwd=password_smb, domain=domain_smb, port=port_smb, name_port=nameport_smb, direct_tcp=directtcp_smb)
#                         home_fs = smb_fs.opendir(share, factory=ClosingSubFS)

#                     except Exception as e:
#                         print(e)
#                         continue
                    
#                     for match in home_fs.glob("**/*"):
#                         temp = match.path
#                         if any(x in match.path.lower() for x in list(keyword.split(','))):
                            
#                             store_path.append(share + temp)
                                
                ############new
                try:
                    smb_fs = fs.smbfs.SMBFS(host=(ip_address_smb, ip_address_smb), username=username_smb,
                                            passwd=password_smb,
                                            domain=domain_smb, port=port_smb, name_port=nameport_smb,
                                            direct_tcp=directtcp_smb)
                    # print(dir(smb_fs))

                    #store_path = []

                    def traverse(path, smb):
                        try:
                            fs = {f: os.path.join(path, f) for f in smb.listdir(path)} 
                            for f in fs:
                                # cur_p = fs[f]
                                cur_p = fs[f].replace('\\', '/')  
                                if smb.isdir(cur_p) and not smb.islink(cur_p):  
                                    traverse(cur_p, smb)
                                elif not smb.islink(cur_p) and smb.isfile(cur_p):  
                                    # store_path.append(cur_p)
                                    if any(x in cur_p.lower() for x in list(keyword.split(','))):  
                                        store_path.append(cur_p)
                                        # print(cur_p)
                        except Exception as e:
                            pass

                        return

                    for share in store_share:
                        traverse(share, smb_fs)
                        #print(store_path)

                except Exception as e:
                    print(e)
                ################new  
  
  
                store_arr = []
                for path in store_path:
                    store_arr.append({'protocol': 'smb', 'path': path})

                for x in store_arr:
                    arr_sensitive.append(x)

            except Exception as e:
                print(e)
                
        
        arr_target.append({'target': target['target'], 'sensitiveFiles': arr_sensitive})
    target_result['targets'] = arr_target
    print(target_result)
    with Api_Hackbot(HACKBOT_BASE_URL, HACKBOT_USERNAME, HACKBOT_PASSWORD) as api:
        print(api.post_to_hackbot(target_result))
