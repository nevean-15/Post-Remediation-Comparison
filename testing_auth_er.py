import requests

 

# Define the URL and headers
url = "https://app.validation.mandiant.com/topology/nodes.json"
headers = {
    "Authorization": "Bearer vdm1_qQE0mwhlC09ovsZgI6guRlUCABBcEkaDfxzIVZGLUAg=",
    "Mandiant-Organization": "UUID 47029589-f9e5-4113-8ada-05c46f46d5b2"
}

 

# Make the GET request
response = requests.get(url, headers=headers)

 

# Print the response (or you can process it as needed)
print(response.text)