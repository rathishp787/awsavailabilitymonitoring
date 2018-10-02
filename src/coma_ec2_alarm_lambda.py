#!/usr/bin/env python
"""

This Lambda function creates a CloudWatch alarm for a specified metric within the EC2 name space.
The function inputs are Instance IDs, Topic ARN, AlarmName, AlarmDescription, MetricName, ComparisionOperator, Threshold, Period, EvaluationPeriods, Statistic, and Unit. 
The function returns a List of the AlarmARNs.

Tested with: 
* 

Set up the following as Lambda environment variables:
    InstanceIDs               Required: Array of Instance ID(s)
    TopicARN                  Required: The topic ARN for SNS
    AlarmName                 Required: Name of the alarm
    AlarmDescription          Required: Description of the alarm
    MetricName                Required: Name of the metric
    ComparisonOperator        Required: Type of comparision operator
    Threshold                 Required: The alarm threshold
    Period                    Required: The Period for the notification
    EvaluationPeriods         Required: The EvaluationPeriods for the notification 
    Statistic                 Required: The statistic for the metric
    Unit                      Required: The unit for the metric

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
        InstanceIDs = os.environ['InstanceIDs']
        TopicARN = os.environ['TopicARN']
        AlarmName = os.environ['AlarmName']
        AlarmDescription = os.environ['AlarmDescription']
        MetricName = os.environ['MetricName']
        ComparisonOperator = os.environ['ComparisonOperator']
        Threshold = float(os.environ['Threshold'])
        Period = int(os.environ['Period'])
        EvaluationPeriods = int(os.environ['EvaluationPeriods'])
        Statistic = os.environ['Statistic']
        Unit = os.environ['Unit']
        TreatMissingData = os.environ['TreatMissingData']
    except:
        print("FATAL ERROR. Lambda environment variable(s) not set.")
        return "Failed"

    #Assign CloudWatch client
    cloudwatch_client = boto3.client('cloudwatch')  

    #Split InstanceIDs on semi-colon ";"
    InstanceIDs_split = InstanceIDs.split(";")

    #List to store alarm ARNs
    AlarmARNList = []

    #Create alarm for every instance in InstanceIDs
    for instance in InstanceIDs_split:
        #Define put_metric_alarm function  
        generate_alarm = cloudwatch_client.put_metric_alarm(
            AlarmName=AlarmName + ":" + instance.strip(),
            ActionsEnabled=True,
            AlarmDescription=AlarmDescription,
            Namespace='AWS/EC2',
            MetricName=MetricName,
            Dimensions=[
                {
                  'Name': 'InstanceId',
                  'Value': instance.strip()
                }
            ],
            ComparisonOperator=ComparisonOperator,
            Threshold=Threshold,
            Period=Period,
            EvaluationPeriods=EvaluationPeriods,
            Statistic=Statistic,
            Unit=Unit,
            AlarmActions=[TopicARN],
            OKActions=[TopicARN],
            TreatMissingData=TreatMissingData
        )
        #Call generate alarm function
        generate_alarm
        #Call Describe Alarm function (returns list of dictionaries)
        alarm = cloudwatch_client.describe_alarms(AlarmNames=[AlarmName + ":" + instance.strip()])
        #Store Alarm ARN for the alarm created above
        for a in alarm['MetricAlarms']:
        	AlarmARNList.append(a['AlarmArn'])

    return AlarmARNList       