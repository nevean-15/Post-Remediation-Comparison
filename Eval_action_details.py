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
EVAL_VID = "S200-053" ## Enter the EVAL or SEQUENCE VID that you want to check for 


## MSV Setup
UUID = "47029589-f9e5-4113-8ada-05c46f46d5b2"   
job_url = "https://app.validation.mandiant.com/simulations/actions/" + EVAL_VID
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

    # Extract and write to CSV
    with open('output.csv', 'w', newline='') as csvfile:
        fieldnames = ['VID', 'RunAs']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write header
        writer.writeheader()

      # Separate actions with "system" in RunAs from others
        system_actions = []
        other_actions = []

        # Iterate through sim_actions
        for action in data_MSV.get('sim_actions', []):
            vid = action.get('vid', '')
            run_as_list = action.get('run_a_list', [])

            # Extract the RunAs values
            run_as_values = [run_as.split(':')[1] for run_as in run_as_list if 'RunAs' in run_as]

            # Check if "system" is in RunAs
            if 'system' in [run_as.lower() for run_as in run_as_values]:
                system_actions.append({'VID': vid, 'RunAs': ', '.join(run_as_values)})
            else:
                other_actions.append({'VID': vid, 'RunAs': ', '.join(run_as_values)})

        # Write actions with "system" in RunAs
        writer.writerows(system_actions)
        # Leave an empty line to differentiate
        writer.writerow({})

        # Write actions without "system" in RunAs
        writer.writerows(other_actions)

else:
    print(f"Request failed with status code {response_MSV.status_code}")


"""     # Iterate through sim_actions
        for action in data_MSV.get('sim_actions', []):
            vid = action.get('vid', '')
            run_as_list = action.get('run_a_list', [])

            # Extract the RunAs values
            run_as_values = [run_as.split(':')[1] for run_as in run_as_list if 'RunAs' in run_as]

            # Write to CSV
            writer.writerow({'VID': vid, 'RunAs': ', '.join(run_as_values)})

else:
    print(f"Request failed with status code {response_MSV.status_code}")"""

"""# Check if the request was successful
if response_MSV.status_code == 200:
    # Load JSON data from the response
    data_MSV = response_MSV.json()

    # Write the JSON data to a file
    with open('output.json', 'w') as f:
        json.dump(data_MSV, f, indent=4)
else:
    print(f"Request failed with status code {response_MSV.status_code}")

"""