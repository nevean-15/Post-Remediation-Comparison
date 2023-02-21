import requests
import json
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings()

# F5 cookie setup
COOKIES = {
    "MRHSession": "1c9f2aa3207f8a24390df124942abc12"
}

# JIRA setup
JIRA_URL = "https://code-jira.am.sony.com/rest/api/2/"
JIRA_DEV_URL = "https://code-jira-dev.am.sony.com/rest/api/2/"

## Testing URL's 
JIRA_DEV_URL_COMMENTS = "https://code-jira-dev.am.sony.com/rest/api/2/issue/SECVAL-7810/comment"
JIRA_PROD_URL_COMMENTS = "https://code-jira.am.sony.com/rest/api/2/issue/SECVAL-891/comment"

JIRA_PROD_URL_LABEL = "https://code-jira.am.sony.com/rest/api/2/issue/"
JIRA_DEV_URL_LABEL = "https://code-jira-dev.am.sony.com/rest/api/2/issue/SECVAL-7810/"
IRA_PROD_URL_COMM_EXT = "/comment/"
JIRA_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}
JIRA_POST_HEADERS = {
    "X-Atlassian-Token": "no-check",
    "Accept": "application/json"
}
JIRA_AUTH = HTTPBasicAuth("svcacct-sc-sv-jira", "Xp]-)x(bmm)EZDq*#PV+")

change_det = "detection_improved"
key = "SECVAL-891"

# Function to Add a Label
def add_labels(key, change):
    addlabel_url = JIRA_PROD_URL_LABEL + "{}".format(key) 
    payload_add = json.dumps({
        "update":{
            "labels":[
                {
                    "add": change
                }
            ]
        }
    })
    response_addlabel = requests.request("PUT", addlabel_url, headers=JIRA_HEADERS, data=payload_add, verify=False, auth=JIRA_AUTH, cookies=COOKIES)
    labeljson = response_addlabel.json()

# Check label
def check_label(k): ## Use jira API for labels
    label_url = JIRA_PROD_URL_LABEL + "{}".format(k)
    # print("urls = {}".format(label_url))
    label_url_response = requests.request("GET", label_url, headers=JIRA_HEADERS, auth=JIRA_AUTH, cookies=COOKIES, verify=False)
    LABEL = label_url_response.json()
    # print(LABEL)
    get_labels = LABEL['fields']['labels']
    # print(get_labels)
    if len(get_labels) > 0:
        return get_labels
    else:
        return "No_labels"
        # print(get_labels)

# Function to Remove a Label
def remove_labels(key, change):
    if check_label(key) == "No_labels":
        add_labels(key, change)
    else:                          
        remlabel_url = JIRA_PROD_URL_LABEL + "{}".format(key) 
        payload_remove = json.dumps({
            "update":{
                "labels":[
                    {
                        "remove": change
                    }
                ]
            }
        })
        requests.request("PUT", remlabel_url, headers=JIRA_HEADERS, data=payload_remove, verify=False, auth=JIRA_AUTH, cookies=COOKIES)
        # labeljson = response_remlabel.json()



remove_labels(key, change_det)


# response_label = requests.request("PUT", JIRA_PROD_URL_LABEL, headers=JIRA_HEADERS, data=payload, verify=False, auth=JIRA_AUTH, cookies=COOKIES)
# labeljson = response_label.json()
# print(labeljson.text)





# Payload for adding comments
comment_url = JIRA_PROD_URL_COMMENTS + "{}".format(key) + JIRA_PROD_URL_COMM_EXT
payload = json.dumps( {
    "body": "This is a comment regarding the quality of the response."
    } )

response_comments = requests.request("POST",JIRA_PROD_URL_COMMENTS, data=payload, headers=JIRA_HEADERS, verify=False, auth=JIRA_AUTH, cookies=COOKIES)
print(response_comments.text)

