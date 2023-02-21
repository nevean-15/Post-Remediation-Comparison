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

# F5 cookie setup
COOKIES = {
    "MRHSession": "c4c82e24ea3c7bc82bd731a3a420657f"
}

# JIRA setup
JIRA_URL = "https://code-jira.am.sony.com/rest/api/2/"
JIRA_DEV_URL = "https://code-jira-dev.am.sony.com/rest/api/2/"
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
JIRA_SEARCH_JQL = "project = SECVAL AND issuetype = 'Attack Simulation' AND 'Epic Link' = SECVAL-882 ORDER BY priority ASC"
JIRA_MAX_RESULTS = "&maxResults=100" # default is 50 so without specification won't grab everything

jira_response = requests.request("GET", JIRA_URL + "search?jql=" + JIRA_SEARCH_JQL + JIRA_MAX_RESULTS, headers=JIRA_HEADERS, verify=False, auth=JIRA_AUTH, cookies=COOKIES)
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

# Print the key and value pair in a table format --------> This formatting will be changed later according to the logic that will be researched later
for key, value in ticketDict.items():
    print(key, "\t", value)
