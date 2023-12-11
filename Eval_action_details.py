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


## MSV Setup
UUID = "47029589-f9e5-4113-8ada-05c46f46d5b2"   
job_url = "https://app.validation.mandiant.com/simulations/actions/S200-053"
headers = {
    'Authorization': f"{MSV_API_KEY}",
    'Mandiant-Organization': f"UUID {UUID}"
}

response_MSV = requests.request("GET", job_url, headers=headers, verify=False)
# print(response_MSV.text)

# Check if the request was successful
if response_MSV.status_code == 200:
    # Load JSON data from the response
    data_MSV = response_MSV.json()

    # Extract VID and RunAs tags
    vid_runas_list = []
    for action in data_MSV.get('sim_actions', []):
        runas_tags = action.get('RunAs', [])
        vid = action.get('VID')
        for runas_tag in runas_tags:
            vid_runas_list.append({'VID': vid, 'RunAs Tags': runas_tag})

    # Write the VID and RunAs tags to a CSV file
    with open('output.csv', 'w', newline='') as csvfile:
        fieldnames = ['VID', 'RunAs Tags']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for item in vid_runas_list:
            writer.writerow(item)

    print("CSV file created successfully!")
else:
    print(f"Request failed with status code {response_MSV.status_code}")

"""# Check if the request was successful
if response_MSV.status_code == 200:
    # Load JSON data from the response
    data_MSV = response_MSV.json()

    # Write the JSON data to a file
    with open('output.json', 'w') as f:
        json.dump(data_MSV, f, indent=4)
else:
    print(f"Request failed with status code {response_MSV.status_code}")"""

