import requests
from jira import JIRA
import jira
import json
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings() # Disables SSL Warnings

# Set up main dictionary
msvDict = {
}

ticketDict = {
}

ticketdict_filters = {

}

msvdict_filters = {
    
}

list_summary = []

# F5 cookie setup
COOKIES = {
    "MRHSession": "71e7db5aa1daa23428939d5c7db59a65"
}

# JIRA setup
JIRA_PROD_URL = "https://code-jira.am.sony.com/rest/api/2/"
JIRA_DEV_URL = "https://code-jira-dev.am.sony.com/rest/api/2/"

JIRA_PROD_URL_COMMENTS = "https://code-jira.am.sony.com/rest/api/2/issue/"
JIRA_DEV_URL_COMMENTS = "https://code-jira-dev.am.sony.com/rest/api/2/issue/"
JIRA_URL_COMM_EXT = "/comment/"

JIRA_PROD_URL_LABEL = "https://code-jira.am.sony.com/rest/api/2/issue/"         
JIRA_DEV_URL_LABEL = "https://code-jira-dev.am.sony.com/rest/api/2/issue/" 

JIRA_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}
JIRA_POST_HEADERS = {
    "X-Atlassian-Token": "no-check",
    "Accept": "application/json"
}
JIRA_AUTH = HTTPBasicAuth("svcacct-sc-sv-jira", "Xp]-)x(bmm)EZDq*#PV+")

# JQL query to pull only Attack simulation issue types
issue_type = "Attack Simulation"
JIRA_SEARCH_JQL = "project = SECVAL AND issuetype = 'Attack Simulation' AND 'Epic Link' = SECVAL-817"
JIRA_MAX_RESULTS = "&maxResults=100" # default is 50 so without specification won't grab everything

## MSV Setup
Job_ID = "16467"
MSV_API_KEY = "Bearer de38ssS27c-uztksgyz4"
filter_data = "target_status,security_technology,alerts, blocking_technologies,filtered_events_by_integration"
job_url = "https://160.33.89.78/v2/jobs/" + Job_ID + ".json?pretty&exclude=" + filter_data
headers = {
    'Authorization': f"{MSV_API_KEY}"
}

## Define Control Area Value
def control_area(Impact):
    malware_defense = ["Protected Theater", "Host CLI", "Phishing Email", "Execute", "Browser Vulnerability"]
    network_monitoring = ["Command and Control", "Malicious File Transfer", "Data Exfiltration", "Data Exfil",
                          "Injection Attempt", "Application Vulnerability", "SQL Injection", "Scanning Activity",
                          "Brute Force", "OWASP", "DNS"]
    email_web = ["Malicious Attachment"]
    malware = "Malware Defenses"
    network = "Network Monitoring and Defense"
    email_and_web = "Email Web Browser and Protections"

    ## Checks for keywords to see what category it should be assigned
    for keyword in malware_defense:
        if keyword in Impact:
            return malware

    for keyword in network_monitoring:
        if keyword in Impact:
            return network

    for keyword in email_web:
        if keyword in Impact:
            return email_and_web

## TODO: Function to get GSIRT system values
def get_gsirt(system):
    malware_defense = ["Protected Theater", "Phishing Email", "Execute"]
    hx_control = ["Host CLI"]
    network_monitoring = ["Command and Control", "Malicious File Transfer", "Data Exfiltration", "Data Exfil",
                          "Application Vulnerability", "Injection", "Scanning Activity", "Brute Force", "OWASP"]
    email_web = ["Malicious Attachment"]

    ## Checks for keywords to see what category it should be assigned
    for keyword in malware_defense:
        if keyword in system:
            return "ePO", "OTHER"

    for keyword in hx_control:
        if keyword in system:
            return "FireEye", "FireEye HX"

    for keyword in network_monitoring:
        if keyword in system:
            return "Firewall", "Palo Alto Appliance"

    for keyword in email_web:
        if keyword in system:
            return "ProofPoint", "OTHER"


# TODO: Function does a string compare on the action name to find the control/component to assign to specific group
# There is probably a better way, but this could work for now as a good example
def findComponent(action_name):
    if "Command and Control" in action_name:
        return "Palo Alto"
    if "Command and Control" and "DNS" in action_name:
        return "INFLOBOX"
    if "Malicious File Transfer" in action_name:
        return "Palo Alto"
    if "Application Vulnerability" in action_name:
        return "Palo Alto"
    if "Data Exfil" in action_name:
        return "Palo Alto"
    if "Data Exfiltration" in action_name:
        return "Palo Alto"
    if "Injection" in action_name:
        return "Palo Alto"
    if "Browser Vulnerability" in action_name:
        return "Palo Alto"
    if "Web Server" in action_name:
        return "Palo Alto"
    if "Lateral Movement" in action_name:
        return "Palo Alto"
    if "WAF Bypass" in action_name:
        return "Palo Alto"
    if "Denial of Service" in action_name:
        return "Palo Alto"
    if "Execute" in action_name:
        return "McAfee"
    if "Scanning Activity" in action_name:
        return "McAfee"
    if "Active Directory" in action_name:
        return "McAfee"
    if "Active Intrusion" in action_name:
        return "McAfee"
    # Put endpoint because we want to be less specific until we are able to match HX and McAfee
    if "Host CLI" in action_name:
        return "FireEye HX"
    if "Download" in action_name:
        return "FireEye HX"
    if "Protected Theater" in action_name:
        return "McAfee"
    if "Phishing Email" in action_name:
        return "Proofpoint"
    if "Web shell" in action_name:
        return "McAfee"
    if "Benign" in action_name:
        return "McAfee"

##TODO: Function for Control Gap Value
def get_control_gap_det(detect):
    if not detect:
        return "Detection"
    else:
        return


def get_control_gap_pre(prevent):
    if not prevent:
        return "Prevention"
    else:
        return
def get_control_gap_ale(alert):
    if not alert:
        return "Alerting"
    else:
        return

# Function to Check label
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
    requests.request("PUT", addlabel_url, headers=JIRA_HEADERS, data=payload_add, verify=False, auth=JIRA_AUTH, cookies=COOKIES)

# Function to Remove a Label - Alternative
def remove_labels(key, change):
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

# Function to Add a Comment
noChanges = "No Change found during RE-TEST"
def add_comments(key, content):
    comment_url = JIRA_DEV_URL_COMMENTS + "{}".format(key) + JIRA_URL_COMM_EXT
    payload_comments = json.dumps( {
        "body": content
        } )

    requests.request("POST",comment_url, data=payload_comments, headers=JIRA_HEADERS, verify=False, auth=JIRA_AUTH, cookies=COOKIES)
    # print(response_comments.text)

## Define Comparison operation
epic_comments = ""

def testing_diff(ticket_filters, msv_filters):
    """ This Function helps to compare two lists and identify the difference and return the value.
        1. If ticket values controls are not equal to MSV job action controls
            a. Check label, if existed, then pass
            b. If the specific label exists, then add a label. (we do this for each control)
        2. If ticket values controls are equal to MSV job action controls
            a. 
        1. Eliminate all possibilities in point 1 by removing labels from the ticket while doing comparison -------> (My Preference)
            a. If changes occur, check for any exisiting labels.
            b. Regardless of the label content, remove all the labels
            c. Add label depending upon the change """

    change_list = [False, False, False]
    change_detection = "detection_improved"
    change_prevention = "prevention_improved"
    change_alarm = "alarm_improved"
    output_string = "" 
    output_string += key + " -" 
    e_comments = ""
    """if the last character from output string != '-', then """
    if ticket_filters != msv_filters:    
        # remove_labels(key, change_detection, change_prevention, change_alarm)
        # Find out which value has changed in the lists.
        if ticket_filters[0] != msv_filters[0]:
            output_string = output_string + " " +  change_detection 
            change_list[0] = True
            if change_detection in check_label(key):                
                pass
            else:
                add_labels(key, change_detection)                

        if ticket_filters[1] != msv_filters[1]:
            output_string = output_string + " " + change_prevention 
            change_list[1] = True
            if change_prevention in check_label(key):
                pass  
            else:
                add_labels(key, change_prevention)                  

        if ticket_filters[2] != msv_filters[2]:
            output_string = output_string + " " + change_alarm
            change_list[2] = True
            if change_alarm in check_label(key):
                pass
            else:
                add_labels(key, change_alarm)
        
        e_comments = e_comments + output_string + "\n"     
        

    # If the controls were same as the original Epic, delete labels if exists and write a comment
    elif ticket_filters == msv_filters:        
        if change_detection in check_label(key):
            remove_labels(key, change_detection)
            """Add comment to say what was done"""
            
        if change_prevention in check_label(key):
            remove_labels(key, change_prevention)
        if change_alarm in check_label(key):
            remove_labels(key, change_alarm)

        add_comments(key, noChanges) # Add comments to the ticket that had no changes

## Jira Items
jira_response = requests.request("GET", JIRA_PROD_URL + "search?jql=" + JIRA_SEARCH_JQL + JIRA_MAX_RESULTS, headers=JIRA_HEADERS, verify=False, auth=JIRA_AUTH, cookies=COOKIES)
jira_json = jira_response.json()
# jira_json = json.loads(jira_response.text)
# with open('data.json', 'w') as outfile:
    # json.dump(jira_json, outfile)
# print(jira_json)


# Get Key and summary for each ticket, populate into sampleDict
for issue in jira_json['issues']:
    vid = issue['fields']['summary'] ## .split(" | ", 1)[0]
    if vid[0] ==  "A": # kludge check for valid action ID
        ticketDict.update({issue['key']: vid})

# Print the key and value pair
# for key, value in ticketDict.items():
#     print(key, "\t", value)

# MSV reponse
response_MSV = requests.request("GET", job_url, headers=headers, verify=False)

## Define MSV job Title
job_raw_data = response_MSV.json()
# with open('data.json', 'w') as outfile:
#     json.dump(job_raw_data, outfile)

job_steps_data = job_raw_data["job_steps"]
for i in job_steps_data:
    job_action_data = i["job_actions"]
    for j in job_action_data:

        ## Ignore if there is a sleep action involved in the job
        if j['action']['action_type'] == 'sleep': continue

        # # Skip Actions that have no issues (True, True, True)
        # if j["detected"] and j["blocked"] and j["alerted"]:
        #     continue

        ## TODO: To assign a value for the Column(Component, GSIRT System) | SOC - "Not Alerted"
        if j["detected"] and j["blocked"] and not j["alerted"]:
            summary = j["vid"] + " " + "|" + " SOC | Not Alarmed" + " | " + j["action_name"]
            component = ""
            gsirt1 = "SPLUNK"
            gsirt2 = "OTHER"
            control_a = "Network Monitoring and Defense"
        else:
            ##TODO: If not SOC then print the below
            summary_det = "Not Detected | " if not j["detected"] else ""
            summary_pre = "Not Prevented | " if not j["blocked"] else ""
            summary = j["vid"] + " " + "|" + f' {findComponent(j["action_name"])}' + " | " + summary_det + \
                        summary_pre + "Not Alarmed" + " | " + j["action_name"]
            component = findComponent(j["action_name"])
            gsirt1, gsirt2 = get_gsirt(j['action_name'])  # GSIRT system value
            control_a = control_area(
                j["action_name"])  # Calculating control area values before values are renamed below

        # print(summary)

        # Calculating control gap values before values are renamed below
        control_gap_det = get_control_gap_det(j["detected"])
        control_gap_pre = get_control_gap_pre(j["blocked"])
        control_gap_ale = get_control_gap_ale(j["alerted"])

        ## Skip Actions that have no issues (True, True, True) 
        if j["detected"] and j["blocked"] and j["alerted"]:
            summary = j["vid"] + " " + "|" + " TRACKING | Detected | Prevented | Alerted" + " | " + j["action_name"]
            control_gap_det = "Detection"
            control_gap_pre = "Prevention"
            control_gap_ale = "Alerting"

        # Boolean to readable
        summary_det = "Not Detected | " if not j["detected"] else ""
        summary_pre = "Not Prevented | " if not j["blocked"] else ""
        if not j["detected"]:
            j["detected"] = "Not Detected"
        else:
            j["detected"] = "Detected"

        # Sets Blocked to a readable value
        if not j["blocked"]:
            j["blocked"] = "Not Prevented"
        else:
            j["blocked"] = "Prevented"

        # Sets Alerted to a readable value
        if not j["alerted"]:
            j["alerted"] = "Not Alarmed"
        else:
            j["alerted"] = "Alarmed"

        if summary[0] ==  "A": # check for valid action ID
            list_summary.append(summary)            
            # msvDict.update({"FIN11-NETWORK": summary})

# for key, value in msvDict.items():
#     print(key, "\t", value)

index = 0
for item in list_summary:
    msvDict[index] = item
    index = index + 1
    #print("item {} = {}".format(index, item))

#print(msvDict)
# for key, value in msvDict.items():
#     print(key, "\t", value)

# To make sure the numbers in the two dictionaries match
if len(ticketDict) == len(msvDict):
    print("Yes, the numbers match")

else:
    print("You Failed Miserably")


for key, value in ticketDict.items():
    jira_actionid = value[:8]
    # if jira_actionid == "A150-984": # To Test the logic with single actionID
    ticket_filters = [] 
    filter_det = "Not Detected" 
    filter_pre = "Not Prevented"
    filter_ala = "Not Alarmed" 
    is_detected = False
    is_prevented = False
    is_alarmed = False    
    if filter_det in value:
        is_detected = True
    ticket_filters.append(is_detected)
    if filter_pre in value:
        is_prevented = True
    ticket_filters.append(is_prevented)
    if filter_ala in value:
        is_alarmed = True       
    ticket_filters.append(is_alarmed)
    ticketdict_filters[jira_actionid] = ticket_filters

# for key, value in ticketdict_filters.items():
#     print(key, "\t", value)
# print("ticket_filters = {}".format(ticket_filters))
# print("is detected = {}, is prevented = {}, is alarmed = {}".format(is_detected, is_prevented, is_alarmed))
# print("msvdict = {}".format(msvDict))

    for title in msvDict.values():        
        msv_actionid = title[:8]
        msv_filters = []        
        if jira_actionid == msv_actionid:            
            filter_det = "Not Detected" 
            filter_pre = "Not Prevented"
            filter_ala = "Not Alarmed" 
            is_detected = False
            is_prevented = False
            is_alarmed = False    
            if filter_det in title:
                is_detected = True
            msv_filters.append(is_detected)
            if filter_pre in title:
                is_prevented = True
            msv_filters.append(is_prevented)
            if filter_ala in title:
                is_alarmed = True  
            msv_filters.append(is_alarmed)
            msvdict_filters[msv_actionid] = msv_filters

            # print("SECVALJIRAID = {}, JiraActionId = {}, ticketdict_filters = {}, msvdict_filters = {}".format(key, jira_actionid, ticketdict_filters[jira_actionid], msvdict_filters[msv_actionid]))
            # print("ticketfilters = {}, msvfilters = {}".format(ticket_filters, msv_filters))
            
            results_compare = testing_diff(ticket_filters, msv_filters)
            
            epic_comments = epic_comments + results_compare
add_comments(EPIC, epic_comments)
# print(epic_comments)            



