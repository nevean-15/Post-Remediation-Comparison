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
from datetime import datetime

urllib3.disable_warnings()  ## Ignore Certificate Issues

## Access the ENV file
## PLEASE FIRST COPY variables.env to variables.env.local, THEN FILL IN THE PASSWORDS IN THE LOCAL FILE ONLY
## THIS IS TO AVOID COMMITTING AND AUTH INFO TO GITLAB

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
output_dir = os.getenv("output_dir") ## output directory to use locally 
ALL_TICKET_INFO = dict()  # dictionary to store ticket number and key (summary)

## Credential & Access Tokens from the Environment file.
MRH_SESSION = "9721b8e0620994f05d8f7a586fe0f56a" ## Session ID (This will be changed once moved to ORC Probably)
#XXX
# SECRET_PASSWORD = os.getenv("SECRET_PASSWORD")  ## Password to Extract the sample attached in the Ticket

MSV_API_KEY = "Bearer vdm1_qQE0mwhlC09ovsZgI6guRlUCABBcEkaDfxzIVZGLUAg="  ## MSV API credentials
sheet_name = "Email_phsishing.csv"
# m_job_id = "1478723"  ## From MSV 
# m_job_id = "2524876"  ## From MSV 
m_job_id = "4430237"  ## From MSV 
# m_job_id = "1593033"  ## From MSV 
Assignee = "GSIRT Security Validation"
#####################################################

## Session Values 
my_cookie = {
    'MRHSession': str(MRH_SESSION)  ## Session ID provided for every new sessions
}

## MSV Setup
UUID = "47029589-f9e5-4113-8ada-05c46f46d5b2"   
# FILTER_DATA = "target_status,security_technology,alerts, blocking_technologies,filtered_events_by_integration"  # Do not require other data
FILTER_DATA = "target_status, security_technology, alerts, blocking_technologies, filtered_events_by_integration"  # Do not require other data
# job_url = "https://app.validation.mandiant.com/v2/jobs/" + m_job_id + ".json?pretty&exclude=" + FILTER_DATA
job_url = "https://app.validation.mandiant.com/v2/jobs/" + m_job_id + ".json?exclude=" + FILTER_DATA
# job_url = "https://app.validation.mandiant.com/v2/jobs/" + m_job_id + ".json"
headers = {
    'Authorization': f"{MSV_API_KEY}",
    'Mandiant-Organization': f"UUID {UUID}"
}

## Define Control Area Value
def control_area(Impact):
    malware_defense = ["Protected Theater", "Host CLI", "Phishing Email", "Execute", "Browser Vulnerability"]
    #XXX - added exploit page to network
    network_monitoring = ["Command and Control", "Malicious File Transfer", "Data Exfiltration", "Data Exfil",
                          "Injection Attempt", "Application Vulnerability", "Web Shell", "SQL Injection", "Scanning Activity",
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
    
## Define Risk Ranking (Will Implement a different Formula, when SOC confirms) 
def risk_ranking(Impact, Detect, Prevent): 
    critical_list = ["Protected Theater", "Malicious Attachment", "Phishing Email", "Execute",
                     "DNS Vulnerability", "Denial of Service", "Application Vulnerability",
                     "Browser Vulnerability", "Remote Services Vulnerability"]

    high_list = ["Active Intrusion", "Command and Control", "Host CLI", "Data Exfiltration", "FTP", "SQL Injection",
                 "Data Exfil", "HTTP Exfil", "HTTPS Exfil", "Web Shell", "Injection Attempt", "OWASP", "Denial of Service"]

    medium_list = ["Malicious File Transfer", "Information Gathering", "Information Gathering - APT41, BESTWAY, SQL Dump", "Brute Force", "Email Exfil", "Evasion Technique", "ICMP Tunnel-based",
                   "DNS Tunnel-based",
                   "Download", "Lateral Movement", "WAF Bypass",
                   "Active Directory", "Web Server", "Exploit Page", "Exploit Kit Activity", "[SVT] [SSL POC] - MFT"]

    low_list = ["Scanning Activity", "Benign", "Discovery"]

    Likelihood_Score = 2
    Exposure_Score = 2
    Impact_Score = None
    ControlBehavior_Score = None

    # Check for keywords to see what category of risk it should be assigned
    for keyword in critical_list:
        if keyword in Impact:
            Impact_Score = 0
            break

    for keyword in high_list:
        if keyword in Impact:
            Impact_Score = 1
            break

    for keyword in medium_list:
        if keyword in Impact:
            Impact_Score = 2
            break

    for keyword in low_list:
        if keyword in Impact:
            Impact_Score = 3
            break

    # Check to see if it was detected, prevented in order to apply score
    if Detect == False and Prevent == False:
        ControlBehavior_Score = 0
    elif Detect == True and Prevent == False:
        ControlBehavior_Score = 1
    elif Detect == True and Prevent == True:
        ControlBehavior_Score = 2
    elif Detect == False and Prevent == True:
        ControlBehavior_Score = 9  # Handle errors (if prevention but no detection)
    
    # Handle cases where some variables are not assigned
    if Likelihood_Score is None:
        Likelihood_Score = 0
    
    if Exposure_Score is None:
        Exposure_Score = 0
    
    if Impact_Score is None:
        Impact_Score = 0
    
    if ControlBehavior_Score is None:
        ControlBehavior_Score = 0

    # Perform calculations on numerical values
    score = (Likelihood_Score + Exposure_Score + Impact_Score) / 3 + ControlBehavior_Score

    if 1 <= score <= 1.33:
        return "Critical"
    elif 1.3333333333333333 <= score <= 2.34:
        return "High"
    elif 2.34 < score <= 3.34:
        return "Medium"
    elif score >= 3.35:
        if score > 7:
            return "Medium"
        else:
            return "Low"
    else:
        return "Total Score Failed"

# print(risk)

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
    if "ICMP" in action_name:
        return "Palo Alto"
    if "HTTP Exfil" or "HTTPS Exfil" in action_name:
        return "Palo Alto"
    if "Injection" in action_name:
        return "Palo Alto"
    if "Browser Vulnerability" in action_name:
        return "Palo Alto"
    if "FTP" in action_name:
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
    if "Web shell" in action_name:
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
    network_monitoring = ["Command and Control", "Malicious File Transfer", "Data Exfiltration", "Data Exfil",
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
    
# Define a function to extract tags from verodin_tags array
def join_tags(tags):
    return ', '.join(tags) if tags else ''

response_MSV = requests.request("GET", job_url, headers=headers, verify=False)
# print(response_MSV.text)


## TODO: Constructing Attack Simulation Ticket

print("\n Dependency Issues - Status - *STARTED* \n")
with open(f'{sheet_name}', mode='w', newline='', encoding="utf-8") as csv_file:
# with open(f'JobID_{m_job_id}_AS.csv', mode='w', encoding="utf-8") as csv_file:
    job_raw_data = response_MSV.json()
    with open('data.json', 'w') as outfile:
        json.dump(job_raw_data, outfile)

    job_steps_data = job_raw_data["job_steps"]
    csv_header_names = ["Action_ID", "Action_Name", "Action_Description",  # Headers for CSV Document
                        "Detected", "Prevented", "SecTech_Component", "Encryption Status", "Risk Level", "Cyber_kill_chain", "Verodin Tags",
                        "Start Time", "End Time", "Raw_event", "Pointer", "Comments"
                        ]
    # csv_header_names = ["Action_ID", "Action_Name", "Action_Description",  # Headers for CSV Document
    #                     "Detected", "Prevented", "SecTech_Component", "Encryption Status"
    #                     ]

    writer = csv.writer(csv_file)
    writer.writerow(csv_header_names)
    # for i in job_steps_data:
    #     job_action_data = i["job_actions"]
    #     for j in job_action_data:

# job_raw_data = response_MSV.json()
# with open('data.json', 'w') as outfile:
#     json.dump(job_raw_data, outfile)
    # name = ""
    job_steps_data = job_raw_data["job_steps"]
    for i in job_steps_data:
        if i['name'] == "Basic":
            encrypted_status = "SSL Configuration Not Applicable"
            group_name = "SSL Configuration Not Applicable"
        elif i['name'] == "SSL Capable (SSL Enabled)":
            encrypted_status = "YES"
            group_name = "SSL Capable (SSL Enabled)"
        elif i['name'] == "SSL Capable (Clear-Text)":
            encrypted_status = "NO"
            group_name = "SSL Capable (Clear-Text)"  
        elif i['name'] == "SSL Capable (Clear Text)":
            encrypted_status = "NO"          
            group_name = "SSL Capable (Clear-Text)"  
        elif i['name'] == "Clear-Text":
            encrypted_status = "NO"
            group_name = "SSL Capable (Clear-Text)" 
        elif i['name'] == "":
            encrypted_status = "YES"
            group_name = "SSL Capable (SSL Enabled)"           

        job_action_data = i["job_actions"]
        for j in job_action_data:

            ## Ignore if there is a sleep action involved in the job
            if j['action']['action_type'] == 'sleep': continue
            if j['status'] == "errored": continue

           # Check if "use_https_connection" key exists in the "run_time" dictionary
            if "use_https_connection" in j["run_time"]:
                https_connection = j["run_time"]["use_https_connection"]
                
                # Determine the Network Action Type
                if https_connection == "true":
                    network_action_type = "SSL"
                elif https_connection == "false":
                    network_action_type = "Non-SSL"
                else:
                    network_action_type = "Unknown"
            else:
                # Handle the case where "use_https_connection" is not present
                network_action_type = "Not Specified"


            # Add code to extract the "name" from "trees" with "root_name" as "Stage of Attack"
            for tree in j['action']['trees']:
                if tree['root_name'] == 'Stage of Attack':
                    stage_of_attack = tree['name']
                    # Now, you can use the 'name' variable as needed
                    # print("Name:", stage_of_attack)

            # Extract the tags from "verodin_tags" array
            verodin_tags = j['action'].get('verodin_tags', [])

            # Join the tags with newlines
            tags_str = join_tags(verodin_tags)

            # Get Filename and Filehash
            file_name, file_hash = getFileNameAndHash(j['action'])

            #Get the command lines executed, if any
            host_commands = getComExec(j['action'])

            ## To pull Detailed ACTION info from the job
            action = j['action']
            action_desc = action['desc']

            ## To find the active VID to pull Website and DNS Specific information from an action
            vid_url = "https://app.validation.mandiant.com/manage_sims/actions/vid/" + str(action["vid"]) + ".json"
            vid_response = requests.request("GET", vid_url, headers=headers, verify=False)
            vid_data = vid_response.json()
            if vid_data["active"] != "null":
                active_vid = vid_data["active"]
            # print(active_vid)

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

            # Assuming 'j' is the dictionary containing the data for the action
            # Extract the 'host_events' and 'integration_events' lists from 'j'
            host_events_list = j.get('host_events', [])
            integration_events_list = j.get('integration_events', [])

            # Initialize 'sectech_component' to None
            sectech_component = None

            # Define a mapping of vendor names to sectech_component values
            vendor_mapping = {
                'McAfee': 'McAfee',
                'VirusScan Enterprise':'McAfee',
                'FireEye': 'FireEye HX',
                'Endpoint Security': 'FireEye HX',
                'Trellix': "Trellix",
                'Palo Alto Networks': 'Palo Alto',
                'Falcon Endpoint Security': 'CrowdStrike',
                'Windows Defender AV': 'Microsoft Defender',
                'Proofpoint': 'Proofpoint'
                # Add more mappings as needed
            }

            # # Check if 'detected' is True
            if j.get('detected'):
                # Combine both host_events and integration_events into a single list
                all_events = host_events_list + integration_events_list

                # Loop through all events to find the vendor value
                for event in all_events:
                    endpoint_product = event.get('endpoint_product')
                    network_device = event.get('network_device')
                    vendor = None

                    if endpoint_product:
                        vendor = endpoint_product.get('vendor', '').strip()
                    elif network_device:
                        vendor = network_device.get('vendor', '').strip()

                    if vendor:
                        # Get the corresponding sectech_component value from the mapping
                        sectech_component = vendor_mapping.get(vendor)
                        break  # Stop after finding the vendor value

            else:
                sectech_component = "None"

            print(sectech_component)  


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

           
                
            summary = j['vid']
            action_Name = j['action_name'] 

            print(summary)

            ## Calculating control gap values before values are renamed below
            control_gap_det = get_control_gap_det(j["detected"])
            control_gap_pre = get_control_gap_pre(j["blocked"])
            control_gap_ale = get_control_gap_ale(j["alerted"])

            ## Skip Actions that have no issues (True, True, True) 
            # if j["detected"] and j["blocked"] and j["alerted"]: continue
            # if j["detected"] and j["blocked"]: continue

                # summary = j["vid"] + " " + "|" + " TRACKING | Detected | Prevented | Alerted" + " | " + j["action_name"]
                # control_gap_det = "Detection"
                # control_gap_pre = "Prevention"
                # control_gap_ale = "Alerting"

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

            # group_name = None
            # encrypted_status = None
            # action_description = f'{action_desc}'
            action_description = (
                ## Formats the information prior to writing to CSV
                f"Description: {action_desc} \n"
                "============================================================================\n"   

                f"Risk Level: {risk} \n"
                "============================================================================\n"            

                "Detection and Prevention results based on testing: \n"
                f"{j['detected']} \n"
                f"{j['blocked']} \n"
                f"{j['alerted']} \n"
                "============================================================================\n"
                "Technical details:\n"
                f"Job ID: {m_job_id}\n"
                # f"SSL Status: {network_action_type}\n"                
                f"Began At: {j['began_at']} \n"
                f"Ended At: {j['ended_at']} \n"
                f"Source HostName & IP: {j['source_actor']['name']} : {j['source_actor']['ip']} \n"
                f"Destination HostName & IP: {j['destination_actor']['hostname']} : {j['destination_actor']['ip']}\n\n"
                "============================================================================\n"
                f"Action Type: {action_type}\n"
                "============================================================================\n"
                "File Information:\n"
                f"File Name: {file_name}\n"
                f"File Hash: {file_hash}\n\n"
                "============================================================================\n"
                f"Commands Executed: \n{host_commands}\n\n"
                "============================================================================\n"
                f"DNS Information:\n "
                f"Query type: {query_type} \n"
                f"Domain: {domain} \n"
                f"Domain Server: {domain_server} \n"
                f"DNS Return Value: {dns_returnvalue} \n\n"
                "============================================================================\n"
                "Web Requests: \n"
                f"Request Type: {request_type}\n"
                f"Request Headers: {request_headers}\n\n"
                "============================================================================\n"
                "Common detections for similar controls: \n"
                f"{declare_field} \n\n"
                "============================================================================\n"
                f"Raw Event: \n{rawLog_as} \n\n"
                f"Host Events: \n{hostLog_as} \n"

            )
            

            # Remaining Jira Fields that can be defined
            fixedVersion = "BAU Activities"  # this is what DE users can adjust later
            RemediationOwner = "Internal"
            Issue_type = "Attack Simulation"
            
            # ## Get the Action Time
            # start_time = datetime.strptime(j['began_at'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%H:%M:%S.%f')[:-3]
            # stop_time = datetime.strptime(j['ended_at'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%H:%M:%S.%f')[:-3]

            # Get the Action Time
            start_time = datetime.strptime(j['began_at'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%H:%M:%S')
            stop_time = datetime.strptime(j['ended_at'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%H:%M:%S')
                        

            sampledata = [summary, action_Name, action_description, res_detected, res_blocked, sectech_component, network_action_type, risk, stage_of_attack, tags_str, start_time, stop_time, "", "", ""]
            # sampledata = summary, action_Name, action_description, res_detected, res_blocked, sectech_component, encrypted_status
            writer.writerow(sampledata)

    print("\nDependency Issues - Status - *COMPLETED* \n")