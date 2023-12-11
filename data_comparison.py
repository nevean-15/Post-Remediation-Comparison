"""import pandas as pd
import csv

# Load Splunk CSV
splunk_data = pd.read_csv('C:\\Users\\7000026782\\Documents\\Automate\\VSC\\pr-comparison\\Code\\splunk_data.csv')

# Load MSV spreadsheet
msv_data = pd.read_csv('C:\\Users\\7000026782\\Documents\\Automate\\VSC\\pr-comparison\\Code\\msv_data.csv')


# Convert _time columns to datetime objects
splunk_data['_time'] = pd.to_datetime(splunk_data['_time'])
msv_data['Start Run Time'] = pd.to_datetime(msv_data['Start Run Time'])
msv_data['Stop Run Time'] = pd.to_datetime(msv_data['Stop Run Time'])

# Sort dataframes by _time
splunk_data.sort_values(by='_time', inplace=True)
msv_data.sort_values (by='Start Run Time', inplace=True)

matched_data = []

for _, action in msv_data.iterrows():
    start_time = action['Start Run Time']
    end_time = action['Stop Run Time']
    action_name = action['Action Name']
    vid = action['VID']

    # Filter Splunk data for events within the action time frame
    events_within_timeframe = splunk_data[(splunk_data['_time'] >= start_time) & (splunk_data['_time'] <= end_time)]

    # if not events_within_timeframe.empty:
    #     # If there are events, add them to the matched_data list
    #     events = " ".join(events_within_timeframe['_raw'].tolist())
    #     matched_data.append({
    #         'VID': vid,
    #         'Events': events
    #     })

    if not events_within_timeframe.empty:
    # If there are events, add them to the matched_data list
        event_count = len(events_within_timeframe)
        matched_data.append({
            'No. of Events': event_count,
            'VID': vid,
            'Events': " ".join(events_within_timeframe['_raw'].tolist())
        })
# Create a new dataframe from the matched data
matched_df = pd.DataFrame(matched_data)

# Save the output to the specified full path
matched_df.to_csv('C:\\Users\\7000026782\\Documents\\Automate\\VSC\\pr-comparison\\Code\\matched_data.csv', index=False)
"""

import pandas as pd
import csv
import re


# Load Splunk CSV
splunk_data = pd.read_csv('C:\\Users\\7000026782\\Documents\\Automate\\VSC\\pr-comparison\\Code\\splunk_data.csv')

# Load MSV spreadsheet
msv_data = pd.read_csv('C:\\Users\\7000026782\\Documents\\Automate\\VSC\\pr-comparison\\Code\\msv_data.csv')

# Define a list of keywords to filter relevant events
keywords = ["Detect", "block", "Detected", "Blocked", "Alert", "Alerted", "Suspicious", "Anomaly", "Security", "Threat", "Incident", "Malicious", "Compromise", "Unauthorized", "Intrusion", "Suspicion", "Abnormal", "Anomalous"]

# Convert _time columns to datetime objects
splunk_data['_time'] = pd.to_datetime(splunk_data['_time'])
msv_data['Start Run Time'] = pd.to_datetime(msv_data['Start Run Time'])
msv_data['Stop Run Time'] = pd.to_datetime(msv_data['Stop Run Time'])

# Sort dataframes by _time
splunk_data.sort_values(by='_time', inplace=True)
msv_data.sort_values(by='Start Run Time', inplace=True)

matched_data = []

for _, action in msv_data.iterrows():
    start_time = action['Start Run Time']
    end_time = action['Stop Run Time']
    vid = action['VID']

    # Filter Splunk data for events within the action time frame and containing keywords
    events_within_timeframe = splunk_data[
        (splunk_data['_time'] >= start_time) & (splunk_data['_time'] <= end_time) &
        splunk_data['_raw'].str.contains("|".join(keywords), case=False, na=False)
    ]

    if not events_within_timeframe.empty:
        # If there are relevant events, add them to the matched_data list
        event_count = len(events_within_timeframe)
        events = " ".join(events_within_timeframe['_raw'].tolist())
        
        # Get the action description and check if events match the description
        action_description = action['Action Description']
        if action_description:
            description_keywords = re.findall(r'\b\w+\b', action_description.lower())
            if any(keyword in events.lower() for keyword in description_keywords):
                matched_data.append({
                    'No. of Events': event_count,
                    'VID': vid,
                    'Events': events
                })

# Create a new dataframe from the matched data
matched_df = pd.DataFrame(matched_data)

# Save the output to the specified full path
matched_df.to_csv('C:\\Users\\7000026782\\Documents\\Automate\\VSC\\pr-comparison\\Code\\matched_data.csv', index=False)
