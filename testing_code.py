import base64  ## Encode and decode base64
import os  ## To perform OS related actions like read/write the file on disk
import io  ## The io module provides the Python interfaces to stream handling, like read/write in-memory data
from io import BytesIO  ## Buffered I/O implementation using an in-memory bytes buffer.
import requests  ## Requests allows you to send HTTP/HTTPS requests (GET and POST)
import json  ## json helps to manipulate any json object or convert other files into json
import urllib3  ## HTTP client to work with URL's
import pyzipper  ## pyzipper helps to compress and password protect inmemory object
from requests.auth import HTTPBasicAuth  ## Attaches HTTP Basic Authentication to the given Request object.
from dotenv import load_dotenv ## Load secrets from file on disk
import csv

urllib3.disable_warnings()  ## Ignore Certificate Issues

## Access the ENV file
## PLEASE FIRST COPY variables.env to variables.env.local, THEN FILL IN THE PASSWORDS IN THE LOCAL FILE ONLY
## THIS IS TO AVOID COMMITTING AND AUTH INFO TO GITLAB
# with open("variables.env", 'rb') as envFile:
#     load_dotenv("variables.env")

## Global variables
filename = ""  ## File related to pcap and samples attached to the ticket
file_name = ""  ## Filename of the Binary
file_hash = ""  ## Hash value of the sample
action_type = ""  ## Individual type of every action (Current Assessment)
Likelihood_Score = ""  ## Risk Calculation Variables
Exposure_Score = ""  ## Risk Calculation Variables
Impact_Score = ""  ## Risk Calculation Variables
ControlBehavior_Score = ""  ## Risk Calculation Variables
score = ""  ## Risk Calculation Variables
assessment_name = "TEST"  ## Jira Assessment Values
gsirt1 = ""  ## Jira Ticket field values
gsirt2 = ""  ## Jira Ticket field values
# output_dir = os.getenv("output_dir") ## output directory to use locally 
output_dir = "C:\\Users\\7000026782\\Documents\\Pcaps1\\" ## output directory to use locally 
ALL_TICKET_INFO = dict()  # dictionary to store ticket number and key (summary)

## Credential & Access Tokens from the Environment file.
# password_jira = os.getenv("password_Jira")  ## Jira Service Account Password from env file
password_Jira = "Xp]-)x(bmm)EZDq*#PV+"  ## Jira Service Account Password from env file
# MRH_SESSION = os.getenv("MRH_SESSION") ## Session ID (This will be changed once moved to ORC Probably)
MRH_SESSION = "81faff00b52db61d2bcd96fe2f006b1f"
#XXX
# SECRET_PASSWORD = os.getenv("SECRET_PASSWORD")  ## Password to Extract the sample attached in the Ticket
# ZIP_PASSWORD = os.getenv("ZIP_PASSWORD")
ZIP_PASSWORD = "infected"
# CRITs_API_KEY = os.getenv("CRITs_API_KEY") ## CRITs API Credentials
CRITs_API_KEY = "&username=jonesa&api_key=76265c0be376a67e1dd40e2014e435b639ccf236" ## CRITs API Credentials
# MSV_API_KEY = os.getenv("MSV_API_KEY")  ## MSV API credentials
MSV_API_KEY = "Bearer vdm1_qQE0mwhlC09ovsZgI6guRlUCABBcEkaDfxzIVZGLUAg="  ## MSV API credentials
# VT_API_KEY = os.getenv("VT_API_KEY") ## Virus Total API Credentials
VT_API_KEY = "a1dc9c3aabc2a4a2b442674d5a333f894f9fca10681182a64b2ae55f4f50647a" ## Virus Total API Credentials
# CRITs_API = os.getenv("CRITs_API") ## CRITs key only
CRITs_API = "76265c0be376a67e1dd40e2014e435b639ccf236" ## CRITs key only
file_path = ''

## THIS MUST BE CHANGED TO THE CURRENT ASSESSSMENT ##
#XXX
EpicLink = "SECVAL-9210"  ## Required Jira Value 
#XXX
# m_job_id = "1478723"  ## From MSV 
m_job_id = "1609004"  ## From MSV 
Assignee = "GSIRT Security Validation"
#####################################################

## Session Values 
my_cookie = {
    'MRHSession': str(MRH_SESSION)  ## Session ID provided for every new sessions
}
 
## Jira Dev Authentication
auth = HTTPBasicAuth("svcacct-sc-sv-jira", password_Jira)
url = "https://code-jira-dev.am.sony.com/rest/api/2/issue"

## Jira Ticket creation headers
headers_jira = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

## Jira Attachment headers
attachmentHeaders_jira = {
    "Accept": "application/json",
    "X-Atlassian-Token": "no-check"
}

## MSV Setup
# filter_data = os.getenv("FILTER_DATA")  # Do not require other data
filter_data = "target_status,security_technology,alerts, blocking_technologies,filtered_events_by_integration"  # Do not require other data
job_url = "https://app.validation.mandiant.com/v2/jobs/" + m_job_id + ".json?pretty&exclude=" + filter_data
headers = {
    'Authorization': f"{MSV_API_KEY}"
}

## CRITs setup
CRITs_URL = "https://crits.gsirt.sony.com/api/v1/samples/?"
## CRITs_HEADERS
CRITs_API_KEY = f"{CRITs_API_KEY}"
CRITs_SEARCH = "c-md5="
CRITs_SHA = "c-sha256="
CRITs_TEST_FILTER = "only=filedata"  # Do not require other data
CRITs_HASH = file_hash

## VT setup
VT_URL = "https://virustotal.com/api/v3/files/"
VT_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "x-apikey": f"{VT_API_KEY}"
}
VT_SHA = file_hash
VT_DL = "/download"

## Download PCAPS from MSV
# def downloadPcapfile(id, fileName):
#     pcap_download = "https://160.33.89.78/manage_sims/actions/download/" + str(id)
#     r = requests.get(pcap_download, headers=headers, verify=False, stream=True)
#     file_path = ""
#     if r.status_code == 200:
#         file_path = os.path.join(output_dir, fileName)
#         with open(file_path, 'wb') as f:
#             for chunk in r.iter_content(chunk_size=8192):  # To Write limited number of Bytes
#                 f.write(chunk)
#             f.flush()
#             f.close()
#     return file_path

# Define a function to check if a ticket with the same action name and issue type exists in the EPIC
# def is_ticket_already_exists(EpicLink, act_name, issue_type):
#     jql = f"project = SECVAL AND [Epic Link] = '{EpicLink}' AND summary ~ '{act_name}' AND issuetype = '{issue_type}'"
#     query_url = f"https://code-jira-dev.am.sony.com/rest/api/2/search?jql=" + jql
    
#     response = requests.get(query_url, headers=headers_jira, cookies=my_cookie, auth=auth, verify=False)
#     error_check = response.json()
#     print(error_check)
#     return error_check['total'] > 0

# def is_ticket_already_exists(EpicLink, act_name, issue_type):
#     jql = f"project = SECVAL AND 'Epic Link' = '{EpicLink}' AND summary ~ '{act_name}' AND issuetype = '{issue_type}'"
#     query_url = "https://code-jira-dev.am.sony.com/rest/api/2/search"

#     payload = {
#         "jql": jql,
#         "startAt": 0,
#         "maxResults": 1,
#         "fields": ["total"]
#     }

#     response = requests.post(query_url, json=payload, headers=headers_jira, cookies=my_cookie, auth=auth, verify=False)
#     result = response.json()
#     print(result)
#     total_issues = result.get('total', 0)
    
#     return total_issues > 0






def downloadPcapfile(id, fileName):
    pcap_download = "https://160.33.89.78/manage_sims/actions/download/" + str(id)
    r = requests.get(pcap_download, headers=headers, verify=False, stream=True)
    file_path = ""
    if r.status_code == 200:
        file_path = os.path.join(output_dir, fileName)
        with open(file_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):  # To Write limited number of Bytes
                f.write(chunk)
            f.flush()
            f.close()
    return file_path, fileName  # Return both file_path and fileName


## Attach PCAPS to Jira Tickets
def attachFileToJira(issueId, filePath, fileName):
    fu = open(filePath, "rb")
    file = {
        "file": (str(fileName), fu, "application-type")
    }

    ## Post request to Jira for the file attachment
    attachmentURL = url + "/" + issueId + "/attachments"
    response_attachment = requests.request("POST", url=attachmentURL, headers=attachmentHeaders_jira,
                                           cookies=my_cookie, auth=auth, verify=False, files=file)
    fu.close()

## Zip the downloaded sample in-memory
def zipTheSample(malname, content):
    #XXX
    SECRET_PASSWORD =  ZIP_PASSWORD.encode()
    with pyzipper.AESZipFile(malname + ".zip", 'w', compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(SECRET_PASSWORD)
        zf.writestr(malname, content)
    malwareSamples.append(malname + ".zip")

## Attach Malware Samples to Jira Tickets
def attachMalSampleToJira(issuekey, sampleFilename):
    payload = open(sampleFilename, 'rb+')
    data = {
        #"file": (sampleFilename + ".zip", mem_zip.getvalue(), "application-type")}
        "file": (sampleFilename, payload, "application-type")}

    ## Block of code creates a post request to Jira for the file attachment
    attachmentURL = url + "/" + issuekey + "/attachments"
    sampleAttach_response = requests.request("POST", url=attachmentURL, headers=attachmentHeaders_jira,
                                             cookies=my_cookie, auth=auth, verify=False, files=data)
    ## Printing the Ticket Value                                         
    if sampleAttach_response.status_code == 200:
        print("Attached the sample to " + issueRes['key'])

    else:
        print("This was such an easy job, even then YOU MISERABLY FAILED!!!")
    #XXX
    payload.close()
    # add line to delete the zip files for clean
    if os.path.exists(file_path):
        os.remove(file_path)  ## To delete the file in the directory after attaching it to Jira successfully
    

##  If Sample Found in Virus Total and not in CRITs
def if_samplefoundin_VT(sampleFilename, filehash, malVTname, content):
    FILES = {
        'filedata': (malVTname, content)
    }
    PARAMS = {  # required by CRITs API
        'upload_type': "file",
        'filename': sampleFilename,
        'source': "testing",
        'username': "jonesa",
        'sha256': filehash,
        'api_key': CRITs_API
    }

    ## Submit the sample to CRITs
    CRITS_POSTURL = "https://crits.gsirt.sony.com/api/v1/samples/"
    crits_post_response = requests.request("POST", CRITS_POSTURL, data=PARAMS,
                                           files=FILES, verify=False, cookies=my_cookie)
    print(crits_post_response.json())

    ## zip and password protect file
    mem_zip = BytesIO()
    zipTheSample(sampleFilename, VT_bytes.getvalue())

## Define Control Area Value
def control_area(Impact):
    malware_defense = ["Protected Theater", "Host CLI", "Phishing Email", "Execute", "Browser Vulnerability"]
    #XXX - added exploit page to network
    network_monitoring = ["Command and Control", "Malicious File Transfer", "Data Exfiltration", "Data Exfil",
                          "Injection Attempt", "Web Shell Activity", "Application Vulnerability", "SQL Injection", "Scanning Activity",
                          "Brute Force", "OWASP", "Exploit Page", "Exploit Kit Activity", "Discovery", "[SVT] [SSL POC] - MFT"]
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

## TODO - Handle risk values that are Inconclusive / Exclude ticket or set High risk
def risk_ranking(Impact, Detect, Prevent):
    critical_list = ["Protected Theater", "Malicious Attachment", "Phishing Email", "Execute",
                     "DNS Vulnerability", "Denial of Service", "Application Vulnerability",
                     "Browser Vulnerability", "Remote Services Vulnerability"]  # Should Malicious Attachment live here?
    high_list = ["Active Intrusion", "Command and Control", "Host CLI", "Data Exfiltration", "SQL Injection",
                 "Data Exfil", "Web Shell", "Injection Attempt", "OWASP", "Denial of Service"]
    medium_list = ["Malicious File Transfer", "Brute Force", "Email Exfil", "Evasion Technique", "DNS Tunnel-based",
                   "Download", "Lateral Movement", "WAF Bypass",
                   "Active Directory", "Web Server", "Exploit Page", "Exploit Kit Activity", "[SVT] [SSL POC] - MFT"]
    low_list = ["Scanning Activity", "Benign", "Discovery"]

    Likelihood_Score = 2  # TTPS (Pretty much everything we are testing)
    Exposure_Score = 2  # Defaults to Most Systems but need a way to find the affected Operation System
    #XXX
    Impact_Score = None
    # Impact_Score = 3 # Found issue, probably with custom actions or something not showing up in this list resulting in "None" initialization, which causes the score calculation to fail
    ControlBehavior_Score = None

    ## Checks for keywords to see what category of risk it should be assigned
    for keyword in critical_list:
        if keyword in Impact:
            Impact_Score = 0

    for keyword in high_list:
        if keyword in Impact:
            Impact_Score = 1

    for keyword in medium_list:
        if keyword in Impact:
            Impact_Score = 2

    for keyword in low_list:
        if keyword in Impact:
            Impact_Score = 3

    ## Checks to see if it was detected, prevented in order to apply score
    if Detect == False and Prevent == False:
        ControlBehavior_Score = 0
    elif Detect == True and Prevent == False:
        ControlBehavior_Score = 1
    elif Detect == True and Prevent == True:
        ControlBehavior_Score = 2
    elif Detect == False and Prevent == True:
        ## This is to catch errors. Generally if you have a prevention there is no detection.
        ControlBehavior_Score = 9
    else:
        ## Fails to inconclusive
        print("Control Behavior Failed")

    ## Perform calculations on numerical values
    score = (Likelihood_Score + Exposure_Score + Impact_Score) / 3 + ControlBehavior_Score

    if 1 <= score <= 1.33:
        return "Critical"
    elif 1.3333333333333333 <= score <= 2.34:
        return "High"
    elif 2.34 < score <= 3.34:
        return "Medium"
    elif score >= 3.35:
        if score > 7:
            return "Medium"  # Will give a this if it blocks with no detection - Consider...
        else:
            return "Low"
    else:
        # print(score)
        return "Total Score Failed"

# TODO: Function does a string compare on the action name to find the control/component to assign to specific group
# There is probably a better way, but this could work for now as a good example
def findComponent(action_name):
    if "Command and Control" in action_name:
        return "Palo Alto"
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
    if "Execute" in action_name:
        return "McAfee"
    if "Scanning Activity" in action_name:
        return "McAfee"
    # Put endpoint because we want to be less specific until we are able to match HX and McAfee
    if "Host CLI" in action_name:
        return "FireEye HX"
    if "Protected Theater" in action_name:
        return "McAfee"
    if "Phishing Email" in action_name:
        return "Proofpoint"
    if "Web Shell" in action_name:
        return "McAfee"
    if "Benign" in action_name:
        return "McAfee"
    #XXX
    # add component for the "exploit page, exploit kit, [svt], etc." basically update this as needed

## TODO: Function to extract FileName and FileHash executed in the action
def getFileNameAndHash(action):
    file_name = 'None'
    file_hash = 'None'
    if 'file_transfer_action' in action:
        file_name = action['file_transfer_action']['file_transfer_library']['orig_file_name']
        file_hash = action['file_transfer_action']['file_transfer_library']['sha256sum']

    elif 'host_cli_action' in action:
        if len(action['host_cli_action']['host_cli_action_file_transfer_libraries']) >= 0:
            for h in action['host_cli_action']['host_cli_action_file_transfer_libraries']:
                file_name = \
                    action['host_cli_action']['host_cli_action_file_transfer_libraries'][0]['file_transfer_library'][
                        'orig_file_name']
                file_hash = \
                    action['host_cli_action']['host_cli_action_file_transfer_libraries'][0]['file_transfer_library'][
                        'sha256sum']
                file_name = \
                    action['host_cli_action']['host_cli_action_file_transfer_libraries'][0]['file_transfer_library'][
                        'orig_file_name']
                file_hash = \
                    action['host_cli_action']['host_cli_action_file_transfer_libraries'][0]['file_transfer_library'][
                        'sha256sum']
    return file_name, file_hash

## TODO: Function to extract Commands executed in the action
def getComExec(commands):
    host_commands = ""
    if 'host_cli_action' in commands:
        if len(commands['host_cli_action']['host_cli_action_steps']) > 0:
            for c in commands['host_cli_action']['host_cli_action_steps']:
                host_commands += c['command'] + "\n"
    if host_commands == "":
        host_commands = 'None'
    return host_commands

## TODO: Function to get GSIRT system values
def get_gsirt(system):
    malware_defense = ["Protected Theater", "Phishing Email", "Execute"]
    hx_control = ["Host CLI"]
    #XXX - added exploit page to network
    network_monitoring = ["Command and Control", "Web Shell Activity","Malicious File Transfer", "Data Exfiltration", "Data Exfil",
                          "Application Vulnerability", "Injection", "Scanning Activity", "Brute Force", "OWASP", "Exploit Page", "Exploit Kit Activity", "[SVT] [SSL POC] - MFT"]
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

response_MSV = requests.request("GET", job_url, headers=headers, verify=False)

## TODO: Constructing Attack Simulation Ticket

print("\nAttack Simulation Issues - Status - *STARTED* \n")
with open(f'JobID_{m_job_id}_AS.csv', mode='w', encoding="utf-8") as csv_file:
    job_raw_data = response_MSV.json()
    with open('data.json', 'w') as outfile:
        json.dump(job_raw_data, outfile)

    job_steps_data = job_raw_data["job_steps"]
    csv_header_names = ["Summary", "Description", "Component", "Fixed Version",  # Headers for CSV Document
                        "Risk Priority", "Remediation Owner", "Control Gap", "Control Gap", "Control Gap",
                        "Control Area",
                        "Assessment Name", "GSIRT System", "GSIRT System", "Assignee", "Issue Type", "Epic Link"]
    writer = csv.writer(csv_file)
    writer.writerow(csv_header_names)
    # for i in job_steps_data:
    #     job_action_data = i["job_actions"]
    #     for j in job_action_data:

# job_raw_data = response_MSV.json()
# with open('data.json', 'w') as outfile:
#     json.dump(job_raw_data, outfile)

    # job_steps_data = job_raw_data["job_steps"]
    for i in job_steps_data:
        job_action_data = i["job_actions"]
        for j in job_action_data:

            ## Ignore if there is a sleep action involved in the job
            if j['action']['action_type'] == 'sleep': continue

            file_name, file_hash = getFileNameAndHash(j['action'])
            host_commands = getComExec(j['action'])

            ## To pull Detailed ACTION info from the job
            action = j['action']
            action_desc = action['desc']

            ## To find the active VID to pull Website and DNS Specific information from an action
            vid_url = "https://app.validation.mandiant.com/manage_sims/actions/vid/" + str(action["vid"]) + ".json"
            vid_response = requests.request("GET", vid_url, headers=headers, verify=False)
            vid_data = vid_response.json()
            active_vid = vid_data["active"]
            # print(active_vid)
            act_name = j['action_name'] 

            action_url = 'https://app.validation.mandiant.com/library/actions.json?id=' + str(active_vid)
            actioninfo_response = requests.request("GET", action_url, headers=headers, verify=False)
            action_data = actioninfo_response.json()
            request_headers = None
            request_type = None
            req_headers = None
            request_body = None
            resp_code = None
            query_type = None
            domain = None
            domain_server = None
            dns_returnvalue = None

            if 'preview_props' in action_data:
                preview_props = action_data['preview_props']
                detail = preview_props['detail']

                ## DNS specific information 
                if preview_props['action_type'] == 'dns':
                    dns_returnvalue = j['run_time']['desc']
                    print(dns_returnvalue)
                    query_type = detail['query_type']
                    domain = detail['domain']
                    domain_server = detail['domain_server']

                ## Website specific information
                elif preview_props['action_type'] == 'website':
                    if detail.get('steps'):
                        steps = detail['steps']
                        for step in steps:
                            request_headers = step['req_headers']
                            request_type = step['request']

            ##TODO: Define Raw Event logs
            ## Write logic to filter Traffic logs and only provide threat logs or other logs that's applicable
            logcount_as = 0
            rawEvent_as = ""
            rawLog_as = ""
            for log in j['integration_events']:
                if "TRAFFIC" in str(log['raw_event']) or "Deny" in str(log['raw_event']): continue
                rawEvent_as += str(log['raw_event']) + "\n\n"
                logcount_as += 1
                if logcount_as >= 3:
                    break

            ## To print "No Applicable Logs found" when there is no Applicable events for the action
            if len(rawEvent_as) > 0:
                for l in rawEvent_as:
                    rawLog_as += l
            else:
                rawLog_as = "No Applicable Logs found"

            ## Fetch Host event logs
            hostLog_as = ""
            hostEvents = []
            for events in j['host_events']:
                if "severe" not in str(events['general_info']).lower(): continue
                description = (
                    f"General Information: {str(events['general_info'])}\n"
                    f"Command Executed: {str(events['cmd'])}\n"
                    f"Computer Name: {str(events['computer'])}\n"
                    f"Source LogFile: {str(events['src_log_file'])}\n"
                    f"Event Type: {str(events['event_type'])}\n"
                    f"User: {str(events['user'])}\n"

                )
                hostEvents.append(description + "\n\n")
                if len(hostEvents) >= 3:
                    break

            if len(hostEvents) > 0:
                for n in hostEvents:
                    hostLog_as += n
            else:
                hostLog_as = "No applicable host events found"

            ## Fetch Common Detection Alerts
            cd_alerts = j['action']
            alerts = 0
            common_detection_alerts = []
            declare_field = ""
            for keyvalue in cd_alerts['common_detection_alerts']:
                source = str(keyvalue['source']) + "\n" if keyvalue['source'] else "None"
                message = str(keyvalue['message']) + "\n" if str(keyvalue['message']) else "None"
                late_alerts = "Source: " + source + "Message: " + message + "\n"
                common_detection_alerts.append(late_alerts)
                alerts += 1
                if alerts >= 3:
                    break

            if len(common_detection_alerts) > 0:
                for k in common_detection_alerts:
                    declare_field += k
            else:
                declare_field = "Source: None" + "\n" + "Message: None" + "\n"

            ## Calculating risk values
            risk = risk_ranking(j["action_name"], j["detected"], j["blocked"])

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
                
            # ## TODO: To assign a value for the Column(Component, GSIRT System) | SOC - "Not Alerted"
            # if j["detected"] and j["blocked"] and not j["alerted"]:
            #     summary = j["vid"] + " " + "|" + " SOC | Not Alarmed" + " | " + j["action_name"]
            #     component = ""
            #     gsirt1 = "SPLUNK"
            #     gsirt2 = "OTHER"
            #     control_a = "Network Monitoring and Defense"
            # else:
            #     ##TODO: If not SOC then print the below
            #     summary_det = "Not Detected | " if not j["detected"] else ""
            #     summary_pre = "Not Prevented | " if not j["blocked"] else ""
            #     summary = j["vid"] + " " + "|" + f' {findComponent(j["action_name"])}' + " | " + summary_det + \
            #             summary_pre + "Not Alarmed" + " | " + j["action_name"]
            #     component = findComponent(j["action_name"])
            #     gsirt1, gsirt2 = get_gsirt(j['action_name'])  # GSIRT system value
            #     control_a = control_area(
            #         j["action_name"])  # Calculating control area values before values are renamed below

            print(summary)

            ## Calculating control gap values before values are renamed below
            control_gap_det = get_control_gap_det(j["detected"])
            control_gap_pre = get_control_gap_pre(j["blocked"])
            control_gap_ale = get_control_gap_ale(j["alerted"])

            ## Skip Actions that have no issues (True, True, True) 
            if j["detected"] and j["blocked"] and j["alerted"]:
                summary = j["vid"] + " " + "|" + " TRACKING | Detected | Prevented | Alerted" + " | " + j["action_name"]
                control_gap_det = "Detection"
                control_gap_pre = "Prevention"
                control_gap_ale = "Alerting"

            ## Gets Assessment Name -  Name must include :: the breaks out
            for tag in (j["tags"]):
                if "::" in tag:
                    assessment_name = tag
                    break

            ## Renaming values from boolean to readable values
            summary_det = "Not Detected | " if not j["detected"] else ""
            summary_pre = "Not Prevented | " if not j["blocked"] else ""
            if not j["detected"]:
                j["detected"] = "Not Detected"
                res_detected = "NO"
            else:
                j["detected"] = "Detected"
                res_detected = "YES"

            ## Sets Blocked to a readable value
            if not j["blocked"]:
                j["blocked"] = "Not Prevented"
                res_blocked = "NO"
            else:
                j["blocked"] = "Prevented"
                res_blocked = "YES"

            ## Sets Alerted to a readable value
            if not j["alerted"]:
                j["alerted"] = "Not Alarmed"
            else:
                j["alerted"] = "Alarmed"

            ## Sets values for action type
            if 'action_type' in j['action']:
                action_type = j['action']['action_type']
            else:
                print('None')

            description = (
                ## Formats the information prior to writing to CSV
                "h3.The following ticket was generated due to a recent assessment by SVT using the MSV platform.\n"
                "============================================================================\n"
                f"*Description:* {action_desc} \n"
                "============================================================================\n"
                f"*Risk Level:* {risk} \n"
                "============================================================================\n"
                f"*Goal:* Review the following results related to {findComponent(j['action_name'])} detection and/or prevention to understand if the MSV test was properly handled.\n"
                "*Objective:* Review the results listed below, investigate potential detection/prevention gaps and attempt to remediate if possible. If remediation is not possible, please provide SVT with a justification for their reporting.\n"
                "*Exit Criteria:* Attempt to remediate potential gaps listed under the results below or provide justification to SVT. Provide what was done to resolve the issue.\n"
                "============================================================================\n"
                "*Detection and Prevention results based on testing:* \n"
                f"{j['detected']} \n"
                f"{j['blocked']} \n"
                f"{j['alerted']} \n"
                "============================================================================\n"
                "*Technical details:*\n"
                f"Job ID: {m_job_id}\n"
                f"Began At: {j['began_at']} \n"
                f"Ended At: {j['ended_at']} \n"
                f"Source HostName & IP: {j['source_actor']['name']} : {j['source_actor']['ip']} \n"
                f"Destination HostName & IP: {j['destination_actor']['hostname']} : {j['destination_actor']['ip']}\n\n"
                "============================================================================\n"
                f"*Action Type:* {action_type}\n"
                "============================================================================\n"
                "*File Information:*\n"
                f"File Name: {file_name}\n"
                f"File Hash: {file_hash}\n\n"
                "============================================================================\n"
                f"*Commands Executed:* \n{host_commands}\n\n"
                "============================================================================\n"
                f"*DNS Information:*\n "
                f"Query type: {query_type} \n"
                f"Domain: {domain} \n"
                f"Domain Server: {domain_server} \n"
                f"DNS Return Value: {dns_returnvalue} \n\n"
                "============================================================================\n"
                "*Web Requests:* \n"
                f"Request Type: {request_type}\n"
                f"Request Headers: {request_headers}\n\n"
                "============================================================================\n"
                "*Common detections for similar controls:* \n"
                f"{declare_field} \n\n"
                "============================================================================\n"
                f"*Raw Event:* \n{rawLog_as} \n\n"
                f"*Host Events:* \n{hostLog_as} \n"

            )

            # Remaining Jira Fields that can be defined
            fixedVersion = "BAU Activities"  # this is what DE users can adjust later
            RemediationOwner = "Internal"
            Issue_type = "Attack Simulation"

            sampledata = summary, description, component, fixedVersion, risk, RemediationOwner, control_gap_det, \
                         control_gap_pre, control_gap_ale, control_a, assessment_name, gsirt1, gsirt2, Assignee, \
                         Issue_type, EpicLink
            writer.writerow(sampledata)
            
            # if not is_ticket_already_exists(EpicLink, act_name, Issue_type):
            ## POST request to Jira for Ticket Creation (Dependency)
            payload = json.dumps({
                "fields": {
                    "project": {
                        "key": "SECVAL"
                    },
                    "summary": f"{summary}",
                    "description": f"{description}",
                    "customfield_15501": f"{EpicLink}",                    
                    # "components": f"{component}",
                    "priority": {"name": f"{risk}"},
                    "customfield_24101": f"{assessment_name}",  # Assessment name
                    "customfield_16404": {"value": gsirt1, "child": {"value": gsirt2}},  # GSIRT Sytem field
                    "customfield_24102": {"value": risk},  # Risk Priority field
                    "customfield_24109": [{"value": control_gap_det}, {"value": control_gap_pre},
                                        {"value": control_gap_ale}], # Control Gap Value
                    "assignee": {"name": Assignee},
                    "customfield_24104": {"value": "Internal"},  # Remediation Owner field
                    "customfield_24110": [{"value": control_a}],  # Control Area field
                    "issuetype": {
                        "name": f"{Issue_type}"
                    }
                }
            })
           
            # Adding linked ticket - Potential Solution
            # https://stackoverflow.com/questions/25991386/jira-rest-api-create-issue-linked-to-another-one

            response_as = requests.request("POST", url, data=payload, headers=headers_jira, cookies=my_cookie,
                                        auth=auth, verify=False)
            # print(response_as.text)
            ticket_info_json = response_as.json()
            print(ticket_info_json)

            ticket_number = ticket_info_json['key'] # This will have the Ticket number (Eg: SECVAL - 12345)
            ALL_TICKET_INFO[summary] = ticket_number # Mapping the AS_Summary with the Ticket Number for linking later

    print("\nAttack Simulation Issues - Status - *COMPLETED* \n")

## TODO: Creating CSV for Dependency Issue Type
print("Dependency Issues - Status - *STARTED* \n")
job_raw_data = response_MSV.json()
job_steps_data = job_raw_data["job_steps"] # Iterating into the json to pull all the required data for ticket creation
for i in job_steps_data:
    job_action_data = i["job_actions"]
    for j in job_action_data:
        
        ## Ignore if there is a sleep action involved in the job
        if j['action']['action_type'] == 'sleep': continue

        file_name, file_hash = getFileNameAndHash(j['action']) # This helps to pull the filename and filehash from the File Transfer or Protected theatre actions
        host_commands = getComExec(j['action']) # Pulling all the commands from the required actions

        ## To pull the Detailed ACTION info from the job
        action = j['action']
        action_desc = action['desc'] # Provides the Action Description for the tickets

        ## Calculating risk values before values are renamed below
        risk = risk_ranking(j["action_name"], j["detected"], j["blocked"])

        ## Helps to find the active VID to pull Website and DNS Specific information of an action
        vid_url = "https://app.validation.mandiant.com/manage_sims/actions/vid/" + str(action["vid"]) + ".json"
        vid_response = requests.request("GET", vid_url, headers=headers, verify=False)
        vid_data = vid_response.json()
        active_vid = vid_data["active"]

        ## Accessing the specific action library to get DNS and WEBSITE specific info 
        action_url = 'https://app.validation.mandiant.com/library/actions.json?id=' + str(active_vid)
        actioninfo_response = requests.request("GET", action_url, headers=headers, verify=False)
        action_data = actioninfo_response.json()
        request_headers = None
        request_type = None
        req_headers = None
        request_body = None
        resp_code = None
        query_type = None
        domain = None
        domain_server = None
        dns_returnvalue = None

        if 'preview_props' in action_data:
            preview_props = action_data['preview_props']
            detail = preview_props['detail']

            ## DNS specific information
            if preview_props['action_type'] == 'dns':
                dns_returnvalue = j['run_time']['desc']
                query_type = detail['query_type']
                domain = detail['domain']
                domain_server = detail['domain_server']

            ## WEBSITE specific information
            elif preview_props['action_type'] == 'website':
                if detail.get('steps'):
                    steps = detail['steps']
                    for step in steps:
                        request_headers = step['req_headers']
                        request_type = step['request']

        ## Fetches Raw Log Information
        logcount_dep = 0
        rawEvent_dep = ""
        rawLog_dep = ""
        for log in j['integration_events']:
            if "TRAFFIC" in str(log['raw_event']) or "Deny" in str(log['raw_event']): continue
            rawEvent_dep += str(log['raw_event']) + "\n\n"
            logcount_dep += 1
            if logcount_dep >= 3:
                break

        ## To print "No Applicable Logs found" when there is no Applicable events for the action
        if len(rawEvent_dep) > 0:
            for s in rawEvent_dep:
                rawLog_dep += s
        else:
            rawLog_dep = "No Applicable Logs found"

        ## Fetches Host event logs
        hostLog_as = ""
        hostEvents = []
        for events in j['host_events']:
            if "severe" not in str(events['general_info']).lower(): continue
            description = (
                f"General Information: {str(events['general_info'])}\n"
                f"Command Executed: {str(events['cmd'])}\n"
                f"Computer Name: {str(events['computer'])}\n"
                f"Source LogFile: {str(events['src_log_file'])}\n"
                f"Event Type: {str(events['event_type'])}\n"
                f"User: {str(events['user'])}\n"

            )
            hostEvents.append(description + "\n\n")
            if len(hostEvents) >= 3:
                break

        if len(hostEvents) > 0:
            for n in hostEvents:
                hostLog_as += n
        else:
            hostLog_as = "No applicable host events found"

        # for events in j['host_events']:
        #     eventcount_as = 0
        #     if "Severe" in str(events['general_info']):
        #         event_as = str(events[2])
        #         eventcount_as += 1
        #         if eventcount_as >= 3:
        #             break
        #

        ## Fetches Common Detection Alerts
        cd_alerts = j['action']
        alerts = 0
        common_detection_alerts = []
        declare_field = ""
        for keyvalue in cd_alerts['common_detection_alerts']:
            source = str(keyvalue['source']) + "\n" if keyvalue['source'] else "None"
            message = str(keyvalue['message']) + "\n" if str(keyvalue['message']) else "None"
            late_alerts = "Source: " + source + "Message: " + message + "\n"
            common_detection_alerts.append(late_alerts)
            alerts += 1
            if alerts >= 3:
                break

        if len(common_detection_alerts) > 0:
            for k in common_detection_alerts:
                declare_field += k
        else:
            declare_field = "Source: None" + "\n" + "Message: None" + "\n"

        ## Skip Actions that have no issues (True, True, True)
        if j["detected"] and j["blocked"]:
            # print("Skipping Action....")  # Can remove after confirmed that is works
            continue

        ## Renaming values from boolean to readable values
        summary_det = "Not Detected | " if not j["detected"] else ""
        summary_pre = "Not Prevented | " if not j["blocked"] else ""
        if not j["detected"]:
            j["detected"] = "Not Detected"
        else:
            j["detected"] = "Detected"

        ## Sets Blocked to a readable value
        if not j["blocked"]:
            j["blocked"] = "Not Prevented"
        else:
            j["blocked"] = "Prevented"

        ## Sets Alerted to a readable value
        if not j["alerted"]:
            j["alerted"] = "Not Alarmed"
        else:
            j["alerted"] = "Alarmed"

        ## Sets values for action type
        if 'action_type' in j['action']:
            action_type = j['action']['action_type']
        else:
            print('None')

        ## Dependency Ticket Summary
        summary_dep = j["vid"] + " | " + f'{findComponent(j["action_name"])}' + " | " + summary_det + \
                      summary_pre + j['alerted'] + " | " + j["action_name"]

        description_dep = (
            ## Formats the information prior to writing to CSV
            "h3.The following ticket was generated due to a recent assessment by SVT using the MSV platform.\n"
            "============================================================================\n"
            f"*Description:* {action_desc} \n"
            "============================================================================\n"
            f"*Risk Level:* {risk} \n"
            "============================================================================\n"
            f"*Goal:* Review the following results related to {findComponent(j['action_name'])} detection and/or prevention to understand if the MSV test was properly handled.\n"
            "*Objective:* Review the results listed below, investigate potential detection/prevention gaps and attempt to remediate if possible. If remediation is not possible, please provide SVT with a justification for their reporting.\n"
            "*Exit Criteria:* Attempt to remediate potential gaps listed under the results below or provide justification to SVT. Provide what was done to resolve the issue.\n"
            "============================================================================\n"
            "*Detection and Prevention results based on testing:* \n"
            f"{j['detected']} \n"
            f"{j['blocked']} \n"
            f"{j['alerted']} \n"
            "============================================================================\n"
            "*Technical details:*\n"
            f"Job ID: {m_job_id}\n"
            f"Began At: {j['began_at']} \n"
            f"Ended At: {j['ended_at']} \n"
            f"Source HostName & IP: {j['source_actor']['name']} : {j['source_actor']['ip']} \n"
            f"Destination HostName & IP: {j['destination_actor']['hostname']} : {j['destination_actor']['ip']}\n\n"
            "============================================================================\n"
            f"*Action Type:* {action_type}\n"
            "============================================================================\n"
            "*File Information:*\n"
            f"File Name: {file_name}\n"
            f"File Hash: {file_hash}\n\n"
            "============================================================================\n"
            f"*Commands Executed:* \n{host_commands}\n\n"
            "============================================================================\n"
            f"*DNS Information:*\n "
            f"Query type: {query_type} \n"
            f"Domain: {domain} \n"
            f"Domain Server: {domain_server} \n"
            f"DNS Return Value: {dns_returnvalue} \n\n"
            "============================================================================\n"
            "*Web Requests:* \n"
            f"Request Type: {request_type}\n"
            f"Request Headers: {request_headers}\n\n"
            "============================================================================\n"
            "*Common detections for similar controls:* \n"
            f"{declare_field} \n\n"
            "============================================================================\n"
            f"*Raw Event:* \n{rawLog_dep} \n\n"
            f"*Host Events:* \n{hostLog_as} \n"

        )

        ## Remaining Jiira Fields that can be defined
        fixedVersion = "BAU Activities"  # this is what DE users can adjust later
        component = findComponent(str(j["action_name"]))
        Assignee = "GSIRT Security Validation"
        GSIRT_pro = "BAU "
        if summary_dep in ALL_TICKET_INFO:  # If Match found - link tickets

            # POST request to Jira for Ticket Creation (Dependency)
            payload = json.dumps({
                "fields": {
                    "project": {
                        "key": "SECVAL"
                    },
                    "summary": f"{summary_dep}",
                    "customfield_15501": f"{EpicLink}",
                    "customfield_25400": {"value": GSIRT_pro},
                    "priority": {"name": f"{risk}"},
                    "description": f"{description_dep}",
                    "assignee": {"name": Assignee},
                    "customfield_14708": {"value": "SCA", "child":
                        {"value": "GISD - Global Information Security Division"}},  # Operating Company
                    "issuetype": {
                        "name": "Dependency"
                    }
                },
                "update": {
                    "issuelinks": [
                        {
                            "add": {
                                "type": {
                                    "name": "Relates",
                                    "inward": "relates to",
                                    "outward": "relates to",
                                },
                                "inwardIssue": {
                                    "key": f"{ALL_TICKET_INFO[summary_dep]}" # Linking DEP ticket to the corresponding AS issue
                                }
                            }
                        }
                    ]
                }
            })
        else:
            payload = json.dumps({
                "fields": {
                    "project": {
                        "key": "SECVAL"
                    },
                    "summary": f"{summary_dep}",
                    "customfield_15501": f"{EpicLink}",
                    "priority": {"name": f"{risk}"},
                    "description": f"{description_dep}",
                    # "components": {"value": "Security Validation"},
                    "assignee": {"name": Assignee},
                    "customfield_14708": {"value": "SCA", "child":
                        {"value": "GISD - Global Information Security Division"}},  # Operating Company
                    "issuetype": {
                        "name": "Dependency"
                    }
                }
            })

        response_dep = requests.request("POST", url, data=payload, headers=headers_jira, cookies=my_cookie,
                                        auth=auth, verify=False)
        print(summary_dep) 

         
        ## Downloads and attaches pcaps to the tickets
        issueRes = response_dep.json()
        # print(issueRes['key'])
        print(issueRes) ## Error Check
        
        id = action['id']
        # if action['action_type'] == "pcap":
        #     fileName = j['vid'] + "-" + str(id) + ".pcap"
        #     file_path = downloadPcapfile(id, fileName) # PCAP download function
        #     ## To attach the downloaded pcap to Jira Tickets
        #     if len(file_path) > 0:
        #         issueId = issueRes["id"]
        #         attachFileToJira(issueId, file_path, fileName) # PCAP attachment function
        #         if os.path.exists(file_path):
        #             os.remove(file_path)  ## To delete the file in the directory after attaching it to Jira successfully
        
        if action['action_type'] == "pcap":
            file_path, fileName = downloadPcapfile(id, fileName)  # Retrieve file_path and fileName
            ## To attach the downloaded pcap to Jira Tickets
            if len(file_path) > 0:
                issueId = issueRes["id"]
                attachFileToJira(issueId, file_path, fileName)  # PCAP attachment function
                if os.path.exists(file_path):
                    os.remove(file_path)  ## To delete the file in the directory after attaching it to Jira successfully


        ## This Block is to grab sample from CRITS / VIRUSTOTAL using the hash
        ## After Downloading, this code also encypt the file password protected and attach to the ticket
        hashresulDes = [] 
        malwareSamples = []
        if file_hash != "None":
            print(file_hash)
            response_CRITS = requests.request("GET",
                                              CRITs_URL + CRITs_SHA + file_hash + "&" + CRITs_TEST_FILTER + "&" + CRITs_API_KEY,
                                              verify=False,
                                              cookies=my_cookie)  # GET request to download the binary in CRITS

            crits_json = response_CRITS.json()

            if bool(crits_json['objects']):  # Sample found in CRTIs
                if type(crits_json['objects'][0]['filedata']) == str:  # Sample has binary data to pull
                    sample = crits_json['objects'][0]['filedata']  # grab the encoded contents to a variable
                    hashresulDes.append("File found in CRITs")

                    ## decode base64 string
                    sample_decode = base64.b64decode(sample)
                    responseBytes = io.BytesIO(sample_decode) # Writing the content in-memory

                    mem_zip = BytesIO()  # Initiating Byte Object

                    ## write to binary file
                    sampleFilename = j["vid"] + "_crits_" + file_hash

                    zipTheSample(sampleFilename, responseBytes.getvalue())

            else:
                ## if NOT in CRITs, check VirusTotal
                ## Generate download link from VT for the SHA256 in question
                ## Download binary file
                response_VT = requests.get(VT_URL + f"{file_hash}" + VT_DL, headers=VT_HEADERS)
                if response_VT.status_code != 200:
                    sampleFound = False
                else:
                    sampleFound = True
                    VT_bytes = io.BytesIO(response_VT.content) # Writing the content in-memory
                    sampleFilename = j["vid"] + "_vt_" + file_hash

                if sampleFound:
                    ## Submit to CRITs
                    ## build params for POST request
                    ## file object
                    hashresulDes.append("File found in VirusTotal and submitted to CRITs.")
                    hashresulDes.append("File found in VirusTotal.")
                    uploadToCrits = str(file_hash + "_VT") # Submitted filename of the sample in CRITs                 
                    if_samplefoundin_VT(sampleFilename, file_hash, uploadToCrits, VT_bytes.getvalue())

                else:  ## attach comment to dictionaries
                    hashresulDes.append("File not found in Crits and Virus Total")

            ## Attach the sample to Jira
            for malwareSample in malwareSamples:
                print(malwareSample)
                mem_zip = BytesIO()
                attachMalSampleToJira(issueRes["id"], malwareSample)

        
        print(hashresulDes)

print("\nDependency Issues - Status - *COMPLETED* \n")


