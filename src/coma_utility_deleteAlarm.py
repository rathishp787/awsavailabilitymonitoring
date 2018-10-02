#!/usr/bin/env python
"""

This Lambda function deletes CloudWatch alarms with the specified naming convention. 

Set up the following as Lambda environment variables:
    AlarmIdentifier               Required: String of the AlarmIdentifier(prefix naming convention)

@author 
@date April 2018       
"""

import boto3
import logging
import os
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    
    #Process Lambda environment variables
    try:
        AlarmIdentifier = os.environ['AlarmIdentifier']
    except:
        print("FATAL ERROR. Lambda environment variable(s) not set.")
        return "Failed"

    #Assign CloudWatch client
    cloudwatch_client = boto3.client('cloudwatch')  

    #List to store alarm ARNs
    AlarmNameList = []
    
    # Create a reusable Paginator
    paginator = cloudwatch_client.get_paginator('describe_alarms')

    for alarm_dict in paginator.paginate():
        for alarm in alarm_dict['MetricAlarms']:
            alarm_name = alarm['AlarmName']
            alarm_prefix = alarm_name.split("/")
            if(alarm_prefix[0] == AlarmIdentifier):
                AlarmNameList.append(alarm_name)
    
    for alarm_name in AlarmNameList:
        cloudwatch_client.delete_alarms(AlarmNames=[alarm_name])
        print("Alarm Deleted: "+alarm_name)
    
    return str(len(AlarmNameList)) + " alarms successfully deleted."