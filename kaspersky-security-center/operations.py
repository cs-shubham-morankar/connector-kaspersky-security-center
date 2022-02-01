"""
Copyright start
Copyright (C) 2008 - 2021 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""
import base64
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('kaspersky_edr')


class KasperskyEDR(object):
    def __init__(self, config):
        self.server_url = config.get('server_url') + ':' + str(config.get('protcol'))
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
            if not self.server_url.endswith('/'):
                self.server_url += '/'
                self.username = config.get('user')
                self.password = config.get('pass')
                self.verify_ssl = config.get('verify_ssl')
                self.Session()

    def Session(self):
        session = requests.Session()
        return session

    def make_request(self, endpoint=None, method='GET', data=None, params=None, files=None, headers=None):
        try:
            url = self.server_url + endpoint
            response = requests.request(method, url, params=params, files=files, data=data, headers=headers,
                                        verify=self.verify_ssl)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(response.text)
                raise ConnectorError({'status_code': response.status_code, 'message': response.reason})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def start_session(self, config, params):
        user = base64.b64encode(config.get('user').encode('utf-8')).decode("utf-8")
        password = base64.b64encode(config.get('pass').encode('utf-8')).decode("utf-8")

        headers = {
            'Authorization': 'KSCBasic user="' + user + '", pass="' + password + '", internal="0"'}
        headers.update({'Content-Type': 'application/json'})

        endpoint = 'api/v1.0/Session.StartSession'
        token = self.make_request(endpoint=endpoint, method='POST', headers=headers)
        return {'X-KSC-Session': token['PxgRetVal'], 'Content-Type': 'application/json'}



def login(config, params):
  kedr = KasperskyEDR(config)
  user = base64.b64encode(config.get('user').encode('utf-8')).decode("utf-8")
  password = base64.b64encode(config.get('pass').encode('utf-8')).decode("utf-8")
  headers = {'Authorization': 'KSCBasic user="' + user + '", pass="' + password + '", internal="0"'}
  headers.update({'Content-Type': 'application/json'})
  endpoint = '/api/v1.0/login'
  session = requests.Session()
  response = kedr.make_request(endpoint=endpoint, method='POST', headers=headers)
  return response

def request_session_post(config, params,data=None ,endpoint=None ,headers=None):
  kedr = KasperskyEDR(config)
  user = base64.b64encode(config.get('user').encode('utf-8')).decode("utf-8")
  password = base64.b64encode(config.get('pass').encode('utf-8')).decode("utf-8")
  protcol = config.get('protcol')
  headers = {'Authorization': 'KSCBasic user="' + user + '", pass="' + password + '", internal="0"'}
  headers.update({'Content-Type': 'application/json'})
  session = requests.Session()
  url = "https://" + config.get('server_url') + ':' + str(protcol) + endpoint
  response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
  return response


def get_hosts_group_static_info(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = 'api/v1.0/HostGroup.GetStaticInfo'
    return kedr.make_request(endpoint=endpoint, method='POST', headers=headers)



def get_host_details(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    host_id = params.get('host_id')
    endpoint = '/api/v1.0/HostGroup.GetHostInfo'
    data = {"strHostName": host_id,
            "pFields2Return": ['KLHST_WKS_OS_NAME', 'KLHST_WKS_LAST_FULLSCAN', 'KLHST_WKS_VIRUS_COUNT',
                               'KLHST_WKS_HOSTNAME', 'KLHST_WKS_DN', 'KLHST_WKS_DNSDOMAIN']}
    response = request_session_post(data=data ,endpoint=endpoint ,headers=headers,config=config ,params=params)
    return json.loads(response.text)


def get_search_results(strAccessor, config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = '/api/v1.0/ChunkAccessor.GetItemsCount'
    data = {"strAccessor": strAccessor}
    response = request_session_post(data=data ,endpoint=endpoint ,headers=headers,config=config ,params=params)
    items_count = json.loads(response.text)['PxgRetVal']
    return json.loads(response.text)

def get_groups(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = '/api/v1.0/HostGroup.FindGroups'
    data = {"wstrFilter": "", "vecFieldsToReturn": ['id', 'name'], "lMaxLifeTime": 100}
    response = request_session_post(data=data ,endpoint=endpoint ,headers=headers,config=config ,params=params)
    strAccessor = json.loads(response.text)['strAccessor']
    items_count = get_search_results(strAccessor, config, params)
    items_count = json.loads(response.text)['PxgRetVal']
    response = get_result(strAccessor, items_count, config, params)
    return response


def get_result(strAccessor, items_count, config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = '/api/v1.0/ChunkAccessor.GetItemsChunk'
    data = {"strAccessor": strAccessor, "nStart": 0, "nCount": items_count}
    results = request_session_post(data=data ,endpoint=endpoint ,headers=headers ,config=config ,params=params)
    results = json.loads(results.text)['pChunk']['KLCSP_ITERATOR_ARRAY']
    return results


def get_listhost_group(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = '/api/v1.0/HostGroup.FindHosts'
    group_id = params.get('group_id')
    data = data = {"wstrFilter": "(KLHST_WKS_GROUPID = " + str(group_id) + ")",
                   "vecFieldsToReturn": ['KLHST_WKS_FQDN',
                                         'KLHST_WKS_HOSTNAME', 'KLHST_WKS_DN', 'KLHST_WKS_OS_NAME'],
                   "lMaxLifeTime": 100}
    response = request_session_post(data=data ,endpoint=endpoint ,headers=headers,config=config ,params=params)
    strAccessor = json.loads(response.text)['strAccessor']
    items_count = get_search_results(strAccessor, config, params)
    items_count = json.loads(response.text)['PxgRetVal']
    response = get_result(strAccessor, items_count, config, params)
    return response


def delete_group(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = '/api/v1.0/HostGroup.RemoveGroup'
    group_id = params.get('group_id')
    Flags = params.get('flag')
    data = {'nGroup': group_id, 'nFlags': Flags}
    response = request_session_post(data=data ,endpoint=endpoint ,headers=headers,config=config ,params=params)
    return (json.loads(response.text))


def add_group(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = '/api/v1.0/HostGroup.AddGroup'
    parent_id = params.get('parent_id')
    name = params.get('name')
    session = kedr.Session()
    protcol = config.get('protcol')
    data = {'pInfo': {'name': name, 'parentId': parent_id}}
    response = request_session_post(data=data ,endpoint=endpoint ,headers=headers,config=config ,params=params)
    return (json.loads(response.text))


def get_software_installed(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = '/api/v1.0/InventoryApi.GetHostInvProducts'
    host_id = params.get('host_id')
    data = {'szwHostId': host_id, }
    response = request_session_post(data=data ,endpoint=endpoint ,headers=headers,config=config ,params=params)
    product_data = json.loads(response.text)
    i = 0
    products = dict()
    for product in product_data['PxgRetVal']['GNRL_EA_PARAM_1']:
        i = i + 1
        name = ("Product Name:", product['value']['DisplayName'])
        version = (("Version"), product['value']['DisplayVersion'])
        ProductID = (("ProductID"), product['value']['ProductID'])
        Publisher = (("Publisher"), product['value']['Publisher'])
        QuietUninstallString = (("Uninstall Command"), product['value']['QuietUninstallString'])
        products[i] = [[name], [version], [ProductID], [Publisher], [QuietUninstallString]]
    return product_data['PxgRetVal']['GNRL_EA_PARAM_1']


def get_product_installed(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = '/api/v1.0/HostGroup.GetHostProducts'
    host_id = params.get('host_id')
    data = {"strHostName": host_id}
    response = request_session_post(data=data ,endpoint=endpoint ,headers=headers,config=config ,params=params)
    product_data = json.loads(response.text)['PxgRetVal']
    products = dict()
    for product in product_data:
        major_ver = list(product_data[product]['value'].keys())[0]
        if 'DisplayName' in product_data[product]['value'][major_ver]['value']:
            name = product_data[product]['value'][major_ver]['value']['DisplayName']
        else:
            name = product
        products[name] = dict()
        if 'ProdVersion' in product_data[product]['value'][major_ver]['value']:
            products[name]['version'] = product_data[product]['value'][major_ver]['value']['ProdVersion']
        else:
            products[name]['version'] = major_ver
        if 'LastUpdateTime' in product_data[product]['value'][major_ver]['value']:
            products[name]['last_update'] = product_data[product]['value'][major_ver]['value']['LastUpdateTime'][
                'value']
        else:
            products[name]['last_update'] = "n/a"
    return products


def list_policies_request(config, params):
  kedr = KasperskyEDR(config)
  headers = kedr.start_session(config, params)
  endpoint = '/api/v1.0/Policy.GetPoliciesForGroup'
  group_id = params.get('group_id')
  data = {"nGroupId": group_id}
  response = request_session_post(data=data ,endpoint=endpoint ,headers=headers,config=config ,params=params)
  return response


def get_policy_request(config, params):
  kedr = KasperskyEDR(config)
  headers = kedr.start_session(config, params)
  endpoint = '/api/v1.0/Policy.GetPolicyData'
  policy_id = params.get('policy_id')
  protcol = config.get('protcol')
  data = {"nPolicy": policy_id}
  response = request_session_post(data=data ,endpoint=endpoint ,headers=headers,config=config ,params=params)
  return response

def add_policy_request(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    endpoint = '/api/v1.0/Policy.AddPolicy'
    KLPOL_DN = params.get('KLPOL_DN')
    nGroupId = params.get('nGroupId')
    KLPOL_PRODUCT = params.get('KLPOL_PRODUCT')
    KLPOL_VERSION = params.get('KLPOL_VERSION')
    KLPOL_GROUP_ID = params.get('KLPOL_GROUP_ID')
    data = {'nGroupId':nGroupId,'pPolicyData': {'KLPOL_DN': KLPOL_DN,
                                           'KLPOL_PRODUCT': KLPOL_PRODUCT,
                            'KLPOL_VERSION': KLPOL_VERSION,'KLPOL_GROUP_ID':KLPOL_GROUP_ID}}
    response = request_session_post(data=data ,endpoint=endpoint ,headers=headers,config=config ,params=params)
    return response
  
def move_hosts(config, params):
    kedr = KasperskyEDR(config)
    headers = kedr.start_session(config, params)
    login(config, params)
    endpoint = '/api/v1.0/HostGroup.MoveHostsToGroup'
    newgroup = params.get('newgroup')
    pHostNames = [params.get('pHostNames')]
    session = kedr.Session()
    protcol = config.get('protcol')
    url = "https://" + config.get('server_url') + ':' + str(protcol) + endpoint
    data =  {'nGroup':newgroup,'pHostNames':pHostNames}
    response = session.post(url=url, headers=headers, data=json.dumps(data), verify=False)
    return response

def _check_health(config):
    kedr = KasperskyEDR(config)
    try:
        params = {}
        res = login(config, params)
        if res:
            logger.info('connector available')
            return True
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


operations = {
    'move_hosts':move_hosts,
    'add_policy_request':add_policy_request,
    'get_policy_request':get_policy_request,
  	'list_policies_request':list_policies_request,
    'get_hosts_group_static_info': get_hosts_group_static_info,
    'get_host_details': get_host_details,
    'get_groups': get_groups,
    'get_listhost_group': get_listhost_group,
    'get_product_installed': get_product_installed,
    'delete_group': delete_group,
    'add_group': add_group,
    'get_software_installed': get_software_installed, }
