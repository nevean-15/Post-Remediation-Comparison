import requests  ## Requests allows you to send HTTP/HTTPS requests (GET and POST)
import json  ## json helps to manipulate any json object or convert other files into json
import urllib3  ## HTTP client to work with URL's
import csv
from datetime import datetime

urllib3.disable_warnings()  ## Ignore Certificate Issues

## Access the ENV file
## PLEASE FIRST COPY variables.env to variables.env.local, THEN FILL IN THE PASSWORDS IN THE LOCAL FILE ONLY
## THIS IS TO AVOID COMMITTING AND AUTH INFO TO GITLAB

## Global variables


MSV_API_KEY = "Bearer vdm1_qQE0mwhlC09ovsZgI6guRlUCABBcEkaDfxzIVZGLUAg="  ## MSV API credentials
sheet_name = "testing.csv"
m_job_id = "1478723"  ## From MSV 
# m_job_id = "2524876"  ## From MSV 
# m_job_id = "1590766"  ## From MSV 
# m_job_id = "1593033"  ## From MSV 
Assignee = "GSIRT Security Validation"
#####################################################

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
    csv_header_names = ["Action_ID", "Start Time", "End Time"]             

    writer = csv.writer(csv_file)
    writer.writerow(csv_header_names)
    job_steps_data = job_raw_data["job_steps"]
    for i in job_steps_data:       

        job_action_data = i["job_actions"]
        for j in job_action_data:

            ## Get VID
            action_id = j['vid']

            ## Get the Action Time
            start_time = datetime.strptime(j['began_at'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%H:%M:%S.%f')[:-3]
            stop_time = datetime.strptime(j['ended_at'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%H:%M:%S.%f')[:-3]
            

            sampledata = [action_id, start_time, stop_time]
            # sampledata = summary, action_Name, action_description, res_detected, res_blocked, sectech_component, encrypted_status
            writer.writerow(sampledata)

    print("\nDependency Issues - Status - *COMPLETED* \n")