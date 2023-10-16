"""
Copyright start
MIT License
Copyright (c) 2023 Fortinet Inc
Copyright end
"""
import base64, json, requests

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('kaspersky-security-center')

errors = {
    400: 'Invalid Argument/Invalid Time Range',
    404: 'Method Not Allowed',
    429: 'OperationLockoutError',
    500: 'Database Unavilable',
    503: 'Maximum Requests Exceeded'
}


class KasperskyEDR(object):
    def __init__(self, config, *args, **kwargs):
        self.username = config.get('username')
        self.password = config.get('password')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/api/v1.0/'.format(url)
        else:
            self.url = url + '/api/v1.0/'
        self.username = base64.b64encode(self.username.encode('utf-8')).decode("utf-8")
        self.password = base64.b64encode(self.password.encode('utf-8')).decode("utf-8")
        self.sslVerify = config.get('verify_ssl')

    def make_rest_call(self, endpoint, headers=None, params=None, data=None, method='GET'):
        try:
            url = self.url + endpoint
            headers = {'Content-Type': 'application/json',
                       'Authorization': 'KSCBasic user="{0}", pass="{1}"'.format(self.username, self.password)
                       }
            response = requests.request(method, url, headers=headers, verify=self.sslVerify, data=data, params=params)
            if response.ok or response.status_code == 200:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response.content
            else:
                raise ConnectorError("{0}".format(errors.get(response.status_code, '')))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def login(config, params):
    kedr = KasperskyEDR(config)
    endpoint = 'login'
    response = kedr.make_rest_call(endpoint=endpoint, method='POST')
    return response


def get_hosts_group_static_info(config, params):
    kedr = KasperskyEDR(config)
    endpoint = 'HostGroup.GetStaticInfo'
    response = kedr.make_rest_call(endpoint=endpoint, method='POST')
    return response


def get_host_details(config, params):
    kedr = KasperskyEDR(config)
    endpoint = 'HostGroup.GetHostInfo'
    payload = {"strHostName": str(params.get('host_id')),
               "pFields2Return": ['KLHST_WKS_OS_NAME', 'KLHST_WKS_LAST_FULLSCAN', 'KLHST_WKS_VIRUS_COUNT',
                                  'KLHST_WKS_HOSTNAME', 'KLHST_WKS_DN', 'KLHST_WKS_DNSDOMAIN']}
    response = kedr.make_rest_call(endpoint=endpoint, method='POST', data=json.dumps(payload))
    
    # Check if the response contains strAccessorId
    if 'strAccessor' not in response:
        return response
    
    str_accessor_id = response['strAccessor']
    # Initialize an empty list to collect chunk data
    chunk_data = []
    
    # Step 2: Use strAccessorId to fetch data page by page
    page = 1
    items_per_page = 100  # Adjust this based on your requirements
    
    while True:
        chunk_endpoint = 'ChunkAccessor.GetItemsChunk'
        chunk_payload = {
            "strAccessorId": str_accessor_id,
            "lFirstItemIndex": (page - 1) * items_per_page,
            "lItemsCount": items_per_page
        }
        
        chunk_response = kedr.make_rest_call(endpoint=chunk_endpoint, method='POST', data=json.dumps(chunk_payload))
        # Extract and append chunk data to the list
        if 'pChunk' in chunk_response:
            chunk_data.append(chunk_response['pChunk'])
        
        # Check if there are more pages to fetch
        if 'bLastChunk' in chunk_response and not chunk_response['bLastChunk']:
            page += 1
        else:
            break
        

    
    # Return the collected chunk data as a JSON array
    return json.dumps(chunk_data)



def get_groups(config, params):
    kedr = KasperskyEDR(config)
    endpoint = 'HostGroup.FindGroups'
    payload = {"wstrFilter": "", "vecFieldsToReturn": ['id', 'name'], "lMaxLifeTime": 100}
    response = kedr.make_rest_call(endpoint=endpoint, method='POST', data=json.dumps(payload))
    return response


def get_listhost_group(config, params):
    kedr = KasperskyEDR(config)
    endpoint = 'HostGroup.FindHosts'
    group_id = params.get('group_id')
    payload = {"wstrFilter": "(KLHST_WKS_GROUPID = " + str(group_id) + ")",
               "vecFieldsToReturn": ['KLHST_WKS_FQDN',
                                     'KLHST_WKS_HOSTNAME', 'KLHST_WKS_DN', 'KLHST_WKS_OS_NAME'],
               "lMaxLifeTime": 100}
    response = kedr.make_rest_call(endpoint=endpoint, method='POST', data=json.dumps(payload))
    
    # Check if the response contains strAccessorId
    if 'strAccessor' not in response:
        return response
    
    str_accessor_id = response['strAccessor']
    # Initialize an empty list to collect chunk data
    chunk_data = []
    
    # Step 2: Use strAccessorId to fetch data page by page
    page = 1
    items_per_page = 100  # Adjust this based on your requirements
    
    while True:
        chunk_endpoint = 'ChunkAccessor.GetItemsChunk'
        chunk_payload = {
            "strAccessorId": str_accessor_id,
            "lFirstItemIndex": (page - 1) * items_per_page,
            "lItemsCount": items_per_page
        }
        
        chunk_response = kedr.make_rest_call(endpoint=chunk_endpoint, method='POST', data=json.dumps(chunk_payload))
        # Extract and append chunk data to the list
        if 'pChunk' in chunk_response:
            chunk_data.append(chunk_response['pChunk'])
        
        # Check if there are more pages to fetch
        if 'bLastChunk' in chunk_response and not chunk_response['bLastChunk']:
            page += 1
        else:
            break
        

    
    # Return the collected chunk data as a JSON array
    return json.dumps(chunk_data)


def delete_group(config, params):
    kedr = KasperskyEDR(config)
    endpoint = 'HostGroup.RemoveGroup'
    payload = {'nGroup': params.get('group_id'), 'nFlags': params.get('flag')}
    response = kedr.make_rest_call(endpoint=endpoint, method='POST', data=json.dumps(payload))
    return response


def add_group(config, params):
    kedr = KasperskyEDR(config)
    endpoint = 'HostGroup.AddGroup'
    payload = {'pInfo': {'name': params.get('name'), 'parentId': config.get('parent_id')}}
    response = kedr.make_rest_call(endpoint=endpoint, method='POST', data=json.dumps(payload))
    return response


def get_software_installed(config, params):
    kedr = KasperskyEDR(config)
    endpoint = 'InventoryApi.GetHostInvProducts'
    payload = {'szwHostId': str(params.get('host_id'))}
    response = kedr.make_rest_call(endpoint=endpoint, method='POST', data=json.dumps(payload))
    return response


def get_product_installed(config, params):
    kedr = KasperskyEDR(config)
    endpoint = 'HostGroup.GetHostProducts'
    payload = {"strHostName": str(params.get('host_id'))}
    response = kedr.make_rest_call(endpoint=endpoint, method='POST', data=json.dumps(payload))
    return response


def list_policies_request(config, params):
    kedr = KasperskyEDR(config)
    endpoint = 'Policy.GetPoliciesForGroup'
    payload = {"nGroupId": params.get('group_id')}
    response = kedr.make_rest_call(endpoint=endpoint, method='POST', data=json.dumps(payload))
    return response


def get_policy_request(config, params):
    kedr = KasperskyEDR(config)
    endpoint = 'Policy.GetPolicyData'
    payload = {"nPolicy": params.get('policy_id')}
    response = kedr.make_rest_call(endpoint=endpoint, method='POST', data=json.dumps(payload))
    return response


def add_policy_request(config, params):
    kedr = KasperskyEDR(config)
    endpoint = 'Policy.AddPolicy'
    payload = {'nGroupId': params.get('nGroupId'), 'pPolicyData': {'KLPOL_DN': params.get('KLPOL_DN'),
                                                                   'KLPOL_PRODUCT': params.get('KLPOL_PRODUCT'),
                                                                   'KLPOL_VERSION': params.get('KLPOL_VERSION'),
                                                                   'KLPOL_GROUP_ID': params.get('KLPOL_GROUP_ID')}}
    response = kedr.make_rest_call(endpoint=endpoint, method='POST', data=json.dumps(payload))
    return response


def move_hosts(config, params):
    kedr = KasperskyEDR(config)
    login(config, params)
    endpoint = 'HostGroup.MoveHostsToGroup'
    pHostNames = [params.get('pHostNames')]
    payload = {'nGroup': params.get('newgroup'), 'pHostNames': pHostNames}
    response = kedr.make_rest_call(endpoint=endpoint, method='POST', data=json.dumps(payload))
    return response


def _check_health(config):
    try:
        res = login(config, params={})
        if res:
            return True
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'move_hosts': move_hosts,
    'add_policy_request': add_policy_request,
    'get_policy_request': get_policy_request,
    'list_policies_request': list_policies_request,
    'get_hosts_group_static_info': get_hosts_group_static_info,
    'get_host_details': get_host_details,
    'get_groups': get_groups,
    'get_listhost_group': get_listhost_group,
    'get_product_installed': get_product_installed,
    'delete_group': delete_group,
    'add_group': add_group,
    'get_software_installed': get_software_installed
}
