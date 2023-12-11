#!/usr/local/bin/python3
import json
import sys
import shutil
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

apiKey = "vdm1_AmVLBjo9gvg9M32pAQQJaqAp1-asvHcQDHVyxMSFLh8="
DIRECTORIP = "app.validation.mandiant.com"

#----- DO NOT EDIT BELOW THIS LINE -----#
session = requests.Session()
if (len(sys.argv)) == 2:
    searchvid = sys.argv[1]
    auth_key = f'Bearer {apiKey}'
    headers = {'Authorization': auth_key}
    session.headers.update(headers)
else:
    searchvid = "null"
    auth_key = f'Bearer {apiKey}'
    headers = {'Authorization': auth_key}
    session.headers.update(headers)

response = session.get("https://" + str(DIRECTORIP) + "/manage_sims/actions.json")
if response.status_code != 200:
    print(response.text)
    print('Unable to get action information from the director.')
    sys.exit(-1)
actionData = json.loads(response.text)

def getVidsFromIds(idList):
    vids = []
    for id in idList:
        for action in actionData:
            if action['id'] == id:
                vids.append(action['vid'])
                break
    return vids

def getActionJson(id):
    response = session.get('https://' + str(DIRECTORIP) + '/library/actions.json?id=' + str(id))
    retVal = json.loads(response.text)
    return retVal

def get_actions():
    action_ids = []
    for action in actionData:
        if action['action_type']:
            action_ids.append(action['id'])
    return action_ids

def get_dns_entries(id_list):
    dns_entries = []
    for id in id_list:
        action_info = getActionJson(id)
        #if (action_info['preview_props']['detail']['request']):
        #    dns_entries.append(action_info['preview_props']['detail']['request'] + ", " + action_info['preview_props']['vid'])
        #dns_entries.append(defang_domain_name(action_info['preview_props']['detail']['domain']) + " - " + action_info['preview_props']['vid'])
        dns_entries.append(action_info)
    return dns_entries

if __name__ == '__main__':
    ids = get_actions()
    vids = getVidsFromIds(ids)

    for x in ids:
        counter = ids.index(x)
        if searchvid != "null":
            if str(vids[counter])==searchvid:
                #print("Position: " + str(counter) + " Library ID: " + str(ids[counter]) + " Action ID (VID): " + str(vids[counter]))
                #print(json.dumps(getActionJson(ids[counter]), indent=2))
                with open("./json/"+str(vids[counter])+".json", "w") as outfile:
                    outfile.write(json.dumps(getActionJson(ids[counter]), indent=2))
        else:
           # print()
            #print("Position: " + str(counter) + " Library ID: " + str(ids[counter]) + " Action ID (VID): " + str(vids[counter]))
            #print(json.dumps(getActionJson(ids[counter]), indent=2))
            #print("================================================================================")
            with open("./json/"+str(vids[counter])+".json", "w") as outfile:
                    outfile.write(json.dumps(getActionJson(ids[counter]), indent=2))

    # Zip the contents of the json directory
    shutil.make_archive('./json_archive', 'zip', './json')
    print('Data has been downloaded and zipped.')
