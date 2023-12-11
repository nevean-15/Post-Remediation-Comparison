"""import requests
import pandas as pd

# Step 1: Access MSV Mandiant Security Validation platform
MSV_API_KEY = "Bearer vdm1_qQE0mwhlC09ovsZgI6guRlUCABBcEkaDfxzIVZGLUAg=" 
UUID = "47029589-f9e5-4113-8ada-05c46f46d5b2"
m_job_id = "your_job_id_here"  # Replace with the actual MSV job ID
FILTER_DATA = "target_status, security_technology, alerts, blocking_technologies, filtered_events_by_integration"
job_url = f"https://app.validation.mandiant.com/v2/jobs/{m_job_id}.json?exclude={FILTER_DATA}"

headers = {
    'Authorization': f"{MSV_API_KEY}",
    'Mandiant-Organization': f"UUID {UUID}"
}

response = requests.get(job_url, headers=headers)
msv_data = response.json()

# Step 2: Access Splunk and Query for events
splunk_query = f"index=*_sec AND ({msv_data['hostname']}) " \
               f"AND sourcetype!=mandiant:advantage:reporting_data " \
               f"AND _time>={msv_data['start_time']-3600} " \
               f"AND _time<={msv_data['end_time']+3600}"

# Replace the placeholder with your actual Splunk credentials and endpoint
splunk_url = "https://your_splunk_endpoint_here"
splunk_headers = {
    'Authorization': 'Splunk your_splunk_token_here',
}

splunk_response = requests.post(splunk_url, headers=splunk_headers, data={'query': splunk_query})
splunk_data = splunk_response.json()

# Step 3: Use Chat GPT API to analyze the action description and CLI log output
def generate_response(prompt):
    # Implement the function to interact with ChatGPT API here
    pass

# Step 4: Compare MSV data to Splunk queried event mapping
csv_data = []

for action in msv_data['actions']:
    action_description = action['action_description']
    start_time = action['start_time']
    end_time = action['end_time']

    prompt = f"Action Description: {action_description}"
    model_response = generate_response(prompt)

    # Add logic to extract and analyze CLI log output from model_response

    # Compare MSV data to Splunk queried event mapping
    relevant_events = splunk_data['events'][
        (splunk_data['events']['_time'] >= start_time) &
        (splunk_data['events']['_time'] <= end_time) &
        (splunk_data['events']['event_type'].isin(["Detection", "Block", "Prevention", "Alert"]))
    ]

    # Count the number of events and concatenate raw event data
    num_events = len(relevant_events)
    raw_events = "\n".join(relevant_events['raw'])

    # Append data to the CSV format
    csv_data.append([msv_data['vid'], num_events, raw_events])

# Step 5: Output data to CSV file
csv_columns = ["VID", "No of Events", "Raw Events"]
output_df = pd.DataFrame(csv_data, columns=csv_columns)
output_df.to_csv("output.csv", index=False)
"""

import requests

splunk_url = 'https://es-splunk.gsirt.sony.com:8089'
username = 'elangovann'
password = 'za_NEveanZg5n9k##W'
search_query = 'search index=* | head 5'

MRH_SESSION = "3236f0633be4ee7c33964239de929d7f"  ## MSV API credentials

## Session Values 
my_cookie = {
    'MRHSession': str(MRH_SESSION)  ## Session ID provided for every new sessions
}

auth = (username, password)
data = {'search': search_query}

response = requests.post(f'{splunk_url}/services/search/jobs/export', auth=auth, data=data, verify=False, cookies=my_cookie)
print(response.text)