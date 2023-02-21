import requests
import json
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings()

# F5 cookie setup
COOKIES = { "MRHSession": "2c6e829a70cadca4107fe56feb8ec95a"}

# JIRA setup
JIRA_PROD_URL_COMMENTS = "https://code-jira.am.sony.com/rest/api/2/issue/SECDEV-569"
JIRA_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json"}
JIRA_POST_HEADERS = {
    "X-Atlassian-Token": "no-check",
    "Accept": "application/json"}
JIRA_AUTH = HTTPBasicAuth("", "")

# Payload for adding comments
payload = { "update": { "labels": [{"add": "test-lab"}]}}
response = requests.put(JIRA_PROD_URL_COMMENTS, json=payload, headers=JIRA_HEADERS, verify=False, auth=JIRA_AUTH, cookies=COOKIES)
response.raise_for_status()
print(response)
print(response.text)