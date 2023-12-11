import requests
import json
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings()

# Set up main dictionary
msvDict = {
}

ticketDict = {
}

list_summary = []

# F5 cookie setup
COOKIES = {
    "MRHSession": "c4c82e24ea3c7bc82bd731a3a420657f"
}

## MSV Setup
Job_ID = "16371"
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




# MSV reponse
response_MSV = requests.request("GET", job_url, headers=headers, verify=False)

## Construct the MSV job Title - 3
## TODO: Constructing Attack Simulation Ticket
job_raw_data = response_MSV.json()
with open('data.json', 'w') as outfile:
    json.dump(job_raw_data, outfile)

job_steps_data = job_raw_data["job_steps"]
for i in job_steps_data:
    job_action_data = i["job_actions"]
    for j in job_action_data:

        ## Ignore if there is a sleep action involved in the job
        if j['action']['action_type'] == 'sleep': continue

        # Skip Actions that have no issues (True, True, True)
        if j["detected"] and j["blocked"] and j["alerted"]:
            continue

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

        print(summary)

        # Calculating control gap values before values are renamed below
        control_gap_det = get_control_gap_det(j["detected"])
        control_gap_pre = get_control_gap_pre(j["blocked"])
        control_gap_ale = get_control_gap_ale(j["alerted"])

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

        # print(summary)
        # vid = summary

        if summary[0] ==  "A": # check for valid action ID
            list_summary.append(summary)            
            # msvDict.update({"FIN11-NETWORK": summary})

# for key, value in msvDict.items():
#     print(key, "\t", value)

#print(list_summary)

index = 0
for item in list_summary:
    msvDict[index] = item
    index = index + 1
    #print("item {} = {}".format(index, item))

#print(msvDict)
for key, value in msvDict.items():
    print(key, "\t", value)
