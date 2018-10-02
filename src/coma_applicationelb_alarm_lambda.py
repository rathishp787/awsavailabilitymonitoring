#!/usr/bin/env python
"""

This Lambda function creates a CloudWatch alarm for a specified metric within the Application ELB name space.
The function inputs are ELB ARN, Topic ARN, AlarmName, AlarmDescription, MetricName, ComparisionOperator, Threshold, Period, EvaluationPeriods, Statistic, and Unit. 
The function returns a List of the AlarmARNs.

Tested with: 
* 

Set up the following as Lambda environment variables:
    appELBARNs                Required: List of ELB ARN(s) (semi-colon seperated line)
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
		appELBARNs = os.environ['appELBARNs']
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
	elbv2_client = boto3.client('elbv2')

    #Split appELBARNs on semi-colon ";"
	appELBARNs_split = appELBARNs.split(";")

    #List to store Alarm ARNs
	AlarmARNList = []

    #Create alarm for every appELB in appELBARNs

	for appELBARN in appELBARNs_split:
		#Split appELBARN on /app/ 
		appELBARN_split = appELBARN.split("/app/")
		#Add app/ to create the LoadBalancer dimension as specified in AWS user guide (the final portion of the load balancer ARN)
		LoadBalancer = "app/" + appELBARN_split[1].strip()
		if (MetricName == "UnHealthyHostCount") or (MetricName == "HealthyHostCount"):
			tg = elbv2_client.describe_target_groups(LoadBalancerArn=appELBARN.strip())
			for tg_iter in tg['TargetGroups']:
				tg_split = tg_iter['TargetGroupArn'].split(":targetgroup/")
				tg_clean = "targetgroup/" + tg_split[1].strip()
				#Define put_metric_alarm function  
				generate_alarm = cloudwatch_client.put_metric_alarm(
					AlarmName=AlarmName + ":" + LoadBalancer + ":" + tg_clean,
					ActionsEnabled=True,
					AlarmDescription=AlarmDescription,
					Namespace='AWS/ApplicationELB',
					MetricName=MetricName,
					Dimensions=[
						{
							'Name': 'LoadBalancer',
							'Value': LoadBalancer
						},
						{
							'Name': 'TargetGroup',
							'Value': tg_clean
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
				alarm = cloudwatch_client.describe_alarms(AlarmNames=[AlarmName + ":" + LoadBalancer + ":" + tg_clean])
				#Store Alarm ARN for the alarm created above
				for a in alarm['MetricAlarms']:
					AlarmARNList.append(a['AlarmArn'])

		elif MetricName == "HTTPCode_Target_4XX_Count":
			generate_alarm = cloudwatch_client.put_metric_alarm(
				AlarmName=AlarmName + ":" + LoadBalancer,
				ActionsEnabled=True,
				AlarmDescription=AlarmDescription,
				Namespace='AWS/ApplicationELB',
				MetricName=MetricName,
				Dimensions=[
					{
						'Name': 'LoadBalancer',
						'Value': LoadBalancer
					}
				],
				ComparisonOperator=ComparisonOperator,
				Threshold=Threshold,
				Period=Period,
				EvaluationPeriods=EvaluationPeriods,
				Statistic=Statistic,
				Unit=Unit,
				AlarmActions=[TopicARN],
				TreatMissingData=TreatMissingData
			)
			#Call generate alarm function
			generate_alarm
			#Call Describe Alarm function (returns list of dictionaries)
			alarm = cloudwatch_client.describe_alarms(AlarmNames=[AlarmName + ":" + LoadBalancer])
			#Store Alarm ARN for the alarm created above
			for a in alarm['MetricAlarms']:
				AlarmARNList.append(a['AlarmArn'])

		elif MetricName == "HTTPCode_Target_5XX_Count":
			generate_alarm = cloudwatch_client.put_metric_alarm(
				AlarmName=AlarmName + ":" + LoadBalancer,
				ActionsEnabled=True,
				AlarmDescription=AlarmDescription,
				Namespace='AWS/ApplicationELB',
				MetricName=MetricName,
				Dimensions=[
					{
						'Name': 'LoadBalancer',
						'Value': LoadBalancer
					}
				],
				ComparisonOperator=ComparisonOperator,
				Threshold=Threshold,
				Period=Period,
				EvaluationPeriods=EvaluationPeriods,
				Statistic=Statistic,
				Unit=Unit,
				AlarmActions=[TopicARN],
				TreatMissingData=TreatMissingData
			)
			#Call generate alarm function
			generate_alarm
			#Call Describe Alarm function (returns list of dictionaries)
			alarm = cloudwatch_client.describe_alarms(AlarmNames=[AlarmName + ":" + LoadBalancer])
			#Store Alarm ARN for the alarm created above
			for a in alarm['MetricAlarms']:
				AlarmARNList.append(a['AlarmArn'])

		else:
			generate_alarm = cloudwatch_client.put_metric_alarm(
				AlarmName=AlarmName + ":" + LoadBalancer,
				ActionsEnabled=True,
				AlarmDescription=AlarmDescription,
				Namespace='AWS/ApplicationELB',
				MetricName=MetricName,
				Dimensions=[
					{
						'Name': 'LoadBalancer',
						'Value': LoadBalancer
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
		alarm = cloudwatch_client.describe_alarms(AlarmNames=[AlarmName + ":" + LoadBalancer])
		#Store Alarm ARN for the alarm created above
		for a in alarm['MetricAlarms']:
			AlarmARNList.append(a['AlarmArn'])

	return AlarmARNList    