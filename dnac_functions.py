
import requests
from requests.auth import HTTPBasicAuth
from dnac_credential import DNAC_USER, DNAC_PASSWORD
from pprint import pprint
from prettytable import PrettyTable
import os,sys
import re
import time
import json




def get_auth_token(Burl):
    """
    Building out Auth request. Using requests.post to make a call to the Auth Endpoint
    """
    global token
    url = Burl.format("dna/system/api/v1/auth/token")
    resp = requests.post(url, auth=HTTPBasicAuth(DNAC_USER, DNAC_PASSWORD),verify=False)
    token = resp.json()['Token']  # Retrieve the Token from the returned JSON
    print("Token Retrieved: {}".format(token))  # Print out the Token


def get_site_health(Burl):
    """
    Returns Overall Health information for all sites
    """
    url = Burl.format("dna/intent/api/v1/site-health?timestamp=") + str(time.time()*1000)
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    resp = requests.get(url, headers=hdr,verify=False)  # Make the Get Request
    site_health = resp.json()
    dnac_devices = PrettyTable(["siteName", "siteId", "parentSiteName", "siteType", "latitude", "longitude",
         "healthy Network Device Percentage", "healthy Clients Percentage","number Of Network Device"])
    dnac_devices.padding_width = 1  # to put width after each entry
    '''for item in site_health['response']:
        dnac_devices.add_row([item["siteName"], item["siteId"], item["parentSiteName"], item["siteType"],
                              item["latitude"], item["longitude"], item["healthyNetworkDevicePercentage"], item["healthyClientsPercentage"],
                              item["numberOfNetworkDevice"]])
    print('\n\n\n\n', dnac_devices)'''
    for item in site_health['response']:
        if item["numberOfNetworkDevice"]!=None:
            dnac_devices.add_row([item["siteName"], item["siteId"], item["parentSiteName"], item["siteType"],
                              item["latitude"], item["longitude"], item["healthyNetworkDevicePercentage"], item["healthyClientsPercentage"],
                              item["numberOfNetworkDevice"]])
    print('\n\n','Site-Health\n', dnac_devices)




def get_network_device(Burl):
    '''Returns list of network devices '''
    url = Burl.format("dna/intent/api/v1/network-device")
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    resp = requests.get(url, headers=hdr,verify=False)  # Make the Get Request
    network_device = resp.json()
    dnac_devices = PrettyTable(["Hostname", "Management Ip Address", "Serial Number", "platform Id", "Software Type", "Software Version","Role", "Up Time","Id"])
    dnac_devices.padding_width = 1  # to put width after each entry
    for item in network_device['response']:
        dnac_devices.add_row([item["hostname"], item["managementIpAddress"], item["serialNumber"], item["platformId"],item["softwareType"], item["softwareVersion"], item["role"], item["upTime"],item["id"]])
    print('\nList of Devices in DNA-\n', dnac_devices)


def get_device_count(Burl):
    url = Burl.format("dna/intent/api/v1/network-device/count")
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    resp = requests.get(url, headers=hdr,verify=False)  # Make the Get Request
    device_count = resp.json()
    print("total number of devices in the setup: ",device_count['response'])


def get_device_list(Burl):
    url = Burl.format("api/v1/network-device")
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    resp = requests.get(url, headers=hdr,verify=False)  # Make the Get Request
    device_list = resp.json()
    dnac_devices = PrettyTable(["Hostname", "Management Ip Address", "Serial Number", "platform Id", "Software Type", "Software Version","Role", "Up Time"])
    dnac_devices.padding_width = 1
    for item in device_list['response']:
        dnac_devices.add_row([item["hostname"], item["managementIpAddress"], item["serialNumber"], item["platformId"],item["softwareType"], item["softwareVersion"], item["role"], item["upTime"]])
    print('\n\nPrinting the device list-\n', dnac_devices,'\n\n')

def create_area_request(name,parentname,Burl):
    payload={"type": "area",
             "site": {
                 "area": {
                     "name": name,"parentName": parentname}}}
    url = Burl.format("dna/system/api/v1/site")
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    try:
        response = requests.post(url, headers=hdr, data=json.dumps(payload), verify=False)
        time.sleep(20)
    except requests.exceptions.RequestException  as cerror:
        print("Error processing request", cerror)
        sys.exit(1)
    return response.json()

def create_building_request(area_name,area_parent,bld_name,area_add,Burl):
    payload = {"type": "building",
               "site": {
                   "area": {
                       "name": area_name,"parentName": area_parent},
                   "building": {
                       "name": bld_name,
                       "address": area_add}
               }
               }
    url = Burl.format("dna/system/api/v1/site")
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    time.sleep(5)
    try:
        response = requests.post(url, headers=hdr, data=json.dumps(payload), verify=False)
        time.sleep(10)
    except requests.exceptions.RequestException  as cerror:
        print("Error processing request", cerror)
        sys.exit(1)
    return response.json()


def create_site(filename,Burl):
    print("\n\nCreating Area in DNA:")
    with open(filename,"r") as f:
        data=json.load(f)
    for key in data['area']:
        print("\ncreating the area having name- {} and parent name- {}".format(key['name'],key['parentName']))
        response = create_area_request(key['name'],key['parentName'],Burl)
        print(response)
    print("\nArea Creation is completed\n\n")
    print("\nCreating Building in Area in DNA:")
    for key in data['building']:
        print("\ncreating the building having area name- {}, area parent name- {}, building name- {}, building address- {}".format(key["area_name"], key["area_parentName"], key["bld_name"], key["bld_address"]))
        response = create_building_request(key["area_name"], key["area_parentName"], key["bld_name"],key["bld_address"],Burl)
        print(json.dumps(response))
    print("\nBuilding Creation is completed","\noverall site creation is completed\n\n")
    time.sleep(30)



def get_device_name_and_device_ip_add(serial_number,Burl):
    url = Burl.format("dna/intent/api/v1/network-device/serial-number/") + serial_number
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    resp = requests.get(url, headers=hdr, verify=False)  # Make the Get Request
    device_list = resp.json()
    return device_list["response"]["managementIpAddress"],device_list["response"]["hostname"]


def add_device_to_site(site_id, ip_add,Burl):
    payload = {"device": [{"ip": ip_add}]}
    url = Burl.format("dna/intent/api/v1/site/")+site_id + "/device"
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    try:
        response = requests.post(url, headers=hdr, data=json.dumps(payload), verify=False)
    except requests.exceptions.RequestException  as cerror:
        print("Error processing request", cerror)
        sys.exit(1)
    return response.json()


def assign_device_to_site(filename,Burl):
    site_id={}
    time.sleep(60)
    url = Burl.format("dna/intent/api/v1/site-health?timestamp=") + str(time.time() * 1000)
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    resp = requests.get(url, headers=hdr, verify=False)  # Make the Get Request
    site_health = resp.json()
    for i in site_health['response']:
        site_id[i['siteName']] = i['siteId']
    pprint(site_id)
    print("\nAssigning device to the newly created site:")
    with open(filename, "r") as f:
        data = json.load(f)
    for key in data['device']:
        print("\nAssigning the device with ip address- {} to the site- {}".format(key['ipadd'], key['siteName']))
        response = add_device_to_site(site_id[key["siteName"]], key['ipadd'],Burl)
        print(response)
        time.sleep(10)
    print("\n\nAdding Devices to Site is complete !!\n\n")
    time.sleep(10)
    get_network_device(Burl)



def device_create(ip_add,username,password,Burl):
    print("\n\n\n\ncreating the device:")
    payload = {
        "cliTransport": "ssh",
        "enablePassword": "yes",
        "ipAddress": [ip_add],
        "password": password,
        "snmpAuthPassphrase": "cisco123",
        "snmpAuthProtocol": "sha",
        "snmpMode": "snmp",
        "snmpPrivPassphrase": "cisco123",
        "snmpPrivProtocol": "sha",
        "snmpROCommunity": "cisco123",
        "snmpRWCommunity": "cisco123",
        "snmpRetry": "3",
        "snmpTimeout": "5",
        "snmpUserName": "admin",
        "snmpVersion": "v2",
        "type": "NETWORK_DEVICE",
        "userName": username
    }
    url = Burl.format("dna/intent/api/v1/network-device")
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    time.sleep(5)
    try:
        response = requests.post(url, headers=hdr, data=json.dumps(payload), verify=False)
        time.sleep(10)
    except requests.exceptions.RequestException  as cerror:
        print("Error processing request", cerror)
        sys.exit(1)
    print("\nDevice created successfully-",response.json()['response'])

def device_update_detail(device_ip,role,Burl):
    print("\n\n\n\nupdating device role:")
    print('\n Before updating-')
    get_network_device(Burl)
    url = Burl.format("dna/intent/api/v1/network-device")
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    resp = requests.get(url, headers=hdr, verify=False)  # Make the Get Request
    network_device = resp.json()
    for key in network_device['response']:
        if key['managementIpAddress']==device_ip:
            device_id=key['id']
    payload = {
        "id": device_id,
        "role": role,
        "roleSource": "MANUAL"
    }
    url = Burl.format("dna/intent/api/v1/network-device/brief")
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    time.sleep(5)
    try:
        response = requests.put(url, headers=hdr, data=json.dumps(payload), verify=False)
        time.sleep(10)
    except requests.exceptions.RequestException  as cerror:
        print("Error processing request", cerror)
        sys.exit(1)
    print("\nDevice role updated successfully-",response.json()['response'])
    print('\n After updating-')
    get_network_device(Burl)


def device_delete(device_ip,Burl):
    print("\n\n\n\nDeleting the device:")
    print('\n Before deleting device- ')
    get_network_device(Burl)
    url = Burl.format("dna/intent/api/v1/network-device")
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    resp = requests.get(url, headers=hdr, verify=False)  # Make the Get Request
    network_device = resp.json()
    for key in network_device['response']:
        if key['managementIpAddress']==device_ip:
            device_id = key['id']
    url = Burl.format("dna/intent/api/v1/network-device/")+device_id
    hdr = {'x-auth-token': token, 'content-type': 'application/json'}
    time.sleep(5)
    try:
        response = requests.delete(url, headers=hdr, verify=False)
        time.sleep(10)
    except requests.exceptions.RequestException  as cerror:
        print("Error processing request", cerror)
        sys.exit(1)
    print("\nDevice deleted successfully-", response.json()['response'])
    print('\n After deleting device- ')
    get_network_device(Burl)




