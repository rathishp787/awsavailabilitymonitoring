import boto3
import os
import json
import ast
import uuid
import csv
import requests
from urllib2 import Request
from urllib2 import urlopen 


print('Imported libraries')

######## Clients
cw  = boto3.client("cloudwatch")
ec2 = boto3.client("ec2")
elb = boto3.client("elbv2")
rds = boto3.client('rds')
lambdaClient = boto3.client('lambda')
iamClient = boto3.client('iam')
s3 = boto3.resource('s3')
#Adding for fix AWSCMF-1032
ssm = boto3.client('ssm')

print('Created clients')
######## Global Variables

EC2_ID_LIST = []
EC2_ID_LIST_STRING = ""
EC2_INPUT_ERROR_LIST = []
EC2_INPUT_ERROR_STRING = ""
EC2_INVENTORY_DICT = {}
ELB_ARN_LIST=[]
ELB_ARN_LIST_STRING=""
ELB_INPUT_ERROR_LIST = []
ELB_INPUT_ERROR_STRING = ""
APP_ELB_INVENTORY_DICT = {}
RDS_IDENTIFIER_LIST = []
RDS_IDENTIFIER_LIST_STRING = ""
RDS_INPUT_ERROR_LIST = []
RDS_INPUT_ERROR_STRING = ""
RDS_INVENTORY_DICT = {}
EC2_ID_LIST_WINDOW = []
EC2_ID_LIST_LINUX = []
EC2_ID_LIST_WINDOWS_STRING = ""
EC2_ID_LIST_LINUX_STRING = ""
EC2_INVENTORY_DICT = {}

def validation_function_rds_ec2_elb(data):
    global EC2_ID_LIST
    global EC2_ID_LIST_STRING
    global EC2_INPUT_ERROR_LIST
    global EC2_INPUT_ERROR_STRING
    global EC2_INVENTORY_DICT
    global ELB_ARN_LIST
    global ELB_ARN_LIST_STRING
    global ELB_INPUT_ERROR_LIST
    global ELB_INPUT_ERROR_STRING
    global APP_ELB_INVENTORY_DICT
    global RDS_IDENTIFIER_LIST
    global RDS_IDENTIFIER_LIST_STRING
    global RDS_INPUT_ERROR_LIST
    global RDS_INPUT_ERROR_STRING
    global RDS_INVENTORY_DICT
    global EC2_ID_LIST_WINDOW
    global EC2_ID_LIST_LINUX 
    global EC2_ID_LIST_WINDOWS_STRING 
    global EC2_ID_LIST_LINUX_STRING 
    global EC2_INVENTORY_DICT

    for i in range(len(data)):
        namespace_label = data[i][1].upper()
        if(namespace_label =="RDS"):
            rds_endpoint_address=data[i][0].strip()
            all_rds = rds.describe_db_instances()
            for dbinstance in all_rds['DBInstances']:
                if dbinstance['Endpoint']['Address'] == rds_endpoint_address:
                    RDS_IDENTIFIER_LIST.append(dbinstance['DBInstanceIdentifier'])
                    RDS_INVENTORY_DICT[rds_endpoint_address] = dbinstance['DBInstanceIdentifier']
                    data[i].append("Exists")
        elif(namespace_label == "EC2"):
            ec2_dns=data[i][0].strip()
            all_ec2 = ec2.describe_instances()
            for reservation in all_ec2['Reservations']:
                for instance in reservation['Instances']:
                    if instance['PrivateDnsName'] == ec2_dns:
                        EC2_ID_LIST.append(instance['InstanceId'])
                        data[i].append("Exists")
                        ##v2
                        # Commenting below for Bug fix : AWSCMF-1032
                        #instance_description = ec2.describe_instances(InstanceIds=[instance['InstanceId']])
                        #image_id = instance_description['Reservations'][0]['Instances'][0]['ImageId']
                        #print("Image id" +image_id+ "found for instance " +instance['InstanceId'])
                        #image_description_dict = ec2.describe_images(ImageIds=[image_id])
                        # Commenting above for Bug fix : AWSCMF-1032

                        #Adding below for fix AWSCMF-1032
                        print("AWSCMF-1032 -Instance is: ")
                        print(instance['InstanceId'])
                        paginator = ssm.get_paginator('describe_instance_information')
                        response_iterator = paginator.paginate(
                                            InstanceInformationFilterList=[
                                                {
                                                    "key": "InstanceIds",
                                                    "valueSet": [
                                                        instance['InstanceId'],
                                                    ]
                                                }
                                            ]
                                        )
                        #Adding above for fix AWSCMF-1032

                        windows_flag=0
                        # Commenting below for Bug fix : AWSCMF-1032
                        #for key,value in image_description_dict['Images'][0].iteritems():
                            #if key=="Platform":
                                #if value=="windows":

                        #Adding below for fix AWSCMF-1032
                        for ssm_dictionary in paginator.paginate():
                            if ssm_dictionary['InstanceInformationList'][0]['PlatformType']=="Windows":
                        #Adding above for fix AWSCMF-1032
                                print("Windows found")
                                windows_flag=1
                                EC2_ID_LIST_WINDOW.append(instance['InstanceId'])
                                EC2_INVENTORY_DICT[ec2_dns] = [instance['InstanceId'],"Windows"]
                        if windows_flag==0:
                            print("Linux found")
                            EC2_ID_LIST_LINUX.append(instance['InstanceId'])
                            EC2_INVENTORY_DICT[ec2_dns] = [instance['InstanceId'],"Linux"]
        elif(namespace_label == "ELB"):
            elb_dns=data[i][0].strip()
            all_elb = elb.describe_load_balancers()
            for loadbalancer in all_elb['LoadBalancers']:
                if loadbalancer['DNSName'] == elb_dns:
                    ##list needed for creating alarm functions
                    ELB_ARN_LIST.append(loadbalancer['LoadBalancerArn'])
                    data[i].append("Exists")
                    ##dictionary for dashboard (don't allow addition if already in list)
                    #if loadbalancer['LoadBalancerArn'] not in ELB_ARN_LIST:
                    app_elb_arn_dict_temp = {}
                    tg_arn_temp = []
                    target_groups = elb.describe_target_groups(LoadBalancerArn=loadbalancer['LoadBalancerArn'])
                    for tg in target_groups['TargetGroups']:
                        tg_arn_temp.append(tg['TargetGroupArn'])
                    app_elb_arn_dict_temp[loadbalancer['LoadBalancerArn']] = tg_arn_temp
                    APP_ELB_INVENTORY_DICT[elb_dns] = app_elb_arn_dict_temp
    
    for i in range(len(data)):
        namespace_label = data[i][1].upper()
        if(namespace_label=="RDS"):
            if not ("Exists" in data[i]):
                RDS_INPUT_ERROR_LIST.append(data[i][0])
        elif(namespace_label=="EC2"):
            if not ("Exists" in data[i]):
                EC2_INPUT_ERROR_LIST.append(data[i][0])
        elif(namespace_label=="ELB"):
            if not("Exists" in data[i]):
                ELB_INPUT_ERROR_LIST.append(data[i][0])

    #Remove duplicates              
    RDS_IDENTIFIER_SET = set(RDS_IDENTIFIER_LIST)
    RDS_IDENTIFIER_LIST = list(RDS_IDENTIFIER_SET)
    EC2_ID_SET = set(EC2_ID_LIST)
    EC2_ID_LIST = list(EC2_ID_SET)
    EC2_ID_WINDOW_SET = set(EC2_ID_LIST_WINDOW)
    EC2_ID_LIST_WINDOW = list(EC2_ID_WINDOW_SET)
    EC2_ID_LINUX_SET = set(EC2_ID_LIST_LINUX)
    EC2_ID_LIST_LINUX = list(EC2_ID_LINUX_SET)
    ELB_ARN_SET = set(ELB_ARN_LIST)
    ELB_ARN_LIST = list(ELB_ARN_SET)

    #Print log to user for RDS
    if not RDS_IDENTIFIER_LIST:
        print("No RDS instances found. Please validate input file")
    elif RDS_INPUT_ERROR_LIST:
        print("Erors found in RDS Instance Input below:")
        print(RDS_INPUT_ERROR_LIST)
        print("Other RDS Instances found. Continuing...")
        print(RDS_IDENTIFIER_LIST)
        RDS_IDENTIFIER_LIST_STRING = ';'.join(RDS_IDENTIFIER_LIST)
    else:
        print("All RDS Instances found. Continuing...")
        print(RDS_IDENTIFIER_LIST)
        RDS_IDENTIFIER_LIST_STRING = ';'.join(RDS_IDENTIFIER_LIST)

    #Print log to user for EC2
    if not EC2_ID_LIST:
        print("No EC2 instances found. Please validate input file")
    elif EC2_INPUT_ERROR_LIST:
        print("Erors found in EC2 Instance Input below:")
        print(EC2_INPUT_ERROR_LIST)
        print("Other EC2 Instances found. Continuing...")
        print(EC2_ID_LIST)
        EC2_ID_LIST_STRING = ';'.join(EC2_ID_LIST)
        ## v2
        EC2_ID_LIST_WINDOWS_STRING = ';'.join(EC2_ID_LIST_WINDOW)
        EC2_ID_LIST_LINUX_STRING = ';'.join(EC2_ID_LIST_LINUX)
    else:
        print("All EC2 Instances found. Continuing...")
        print(EC2_ID_LIST)
        EC2_ID_LIST_STRING = ';'.join(EC2_ID_LIST)
        ## v2
        EC2_ID_LIST_WINDOWS_STRING = ';'.join(EC2_ID_LIST_WINDOW)
        EC2_ID_LIST_LINUX_STRING = ';'.join(EC2_ID_LIST_LINUX)

    #Print log to user for ELB
    if not ELB_ARN_LIST:
        print("No ELBs found. Please validate input file")
    elif ELB_INPUT_ERROR_LIST:
        print("Erors found in ELB Input below:")
        print(ELB_INPUT_ERROR_LIST)
        print("Other ELBs found. Continuing...")
        print(ELB_ARN_LIST)
        ELB_ARN_LIST_STRING = ';'.join(ELB_ARN_LIST_STRING)
    else:
        print("All ELBs found. Continuing...")
        print(ELB_ARN_LIST)
        ELB_ARN_LIST_STRING = ';'.join(ELB_ARN_LIST)

def send_response(event, context, responseStatus, responseData):
    print(event)
    responseBody = {'Status': responseStatus,
                    'Reason': 'See the details in CloudWatch Log Stream: ' + context.log_stream_name,
                    'PhysicalResourceId': context.log_stream_name,
                    'StackId': event['StackId'],
                    'RequestId': event['RequestId'],
                    'LogicalResourceId': event['LogicalResourceId'],
                    'Data': responseData}

    req = None
    try:
        req = requests.put(event['ResponseURL'], data=json.dumps(responseBody))

        if req.status_code != 200:
            print(req.text)
            raise Exception('Recieved non 200 response while sending response to CFN.')
        return

    except requests.exceptions.RequestException as e:
        if req != None:
            print(req.text)
        print(e)
        raise

def lambda_handler(event, context):
    global EC2_ID_LIST
    global EC2_ID_LIST_STRING
    global EC2_INPUT_ERROR_LIST
    global EC2_INPUT_ERROR_STRING
    global ELB_ARN_LIST
    global ELB_ARN_LIST_STRING
    global ELB_INPUT_ERROR_LIST
    global ELB_INPUT_ERROR_STRING
    global RDS_IDENTIFIER_LIST
    global RDS_IDENTIFIER_LIST_STRING
    global RDS_INPUT_ERROR_LIST
    global RDS_INPUT_ERROR_STRING
    global APP_ELB_INVENTORY_DICT
    global EC2_ID_LIST_WINDOW
    global EC2_ID_LIST_LINUX 
    global EC2_ID_LIST_WINDOWS_STRING 
    global EC2_ID_LIST_LINUX_STRING 
    global EC2_INVENTORY_DICT
    responseStatus = 'SUCCESS'
    responseData = {}
    try:
        EMAIL_ADDRESS_STRING_LIST = os.environ['EMAIL_ADDRESS_STRING_LIST']   
        TOPIC_NAME = os.environ['DASHBOARD_NAME']+"_Alarm_Topic"
        DASHBOARD_NAME = os.environ['DASHBOARD_NAME']
        CPU_UTILIZATION_CRITICAL_THRESHOLD = os.environ['CPU_UTILIZATION_CRITICAL_THRESHOLD']
        CPU_UTILIZATION_WARNING_THRESHOLD = os.environ['CPU_UTILIZATION_WARNING_THRESHOLD']
        MEMORY_UTILIZATION_WARNING_THRESHOLD = os.environ['MEMORY_UTILIZATION_WARNING_THRESHOLD']
        MEMORY_UTILIZATION_CRITICAL_THRESHOLD = os.environ['MEMORY_UTILIZATION_CRITICAL_THRESHOLD']
        MEMORY_UTILIZATION_WARNING_THRESHOLD_WIN = os.environ['MEMORY_UTILIZATION_WARNING_THRESHOLD_WIN']
        MEMORY_UTILIZATION_CRITICAL_THRESHOLD_WIN = os.environ['MEMORY_UTILIZATION_CRITICAL_THRESHOLD_WIN']
        DISK_UTILIZATION_WARNING_THRESHOLD = os.environ['DISK_UTILIZATION_WARNING_THRESHOLD']
        DISK_UTILIZATION_CRITICAL_THRESHOLD = os.environ['DISK_UTILIZATION_CRITICAL_THRESHOLD']
        UNHEALTHY_HOST_WARNING_THRESHOLD = os.environ['UNHEALTHY_HOST_WARNING_THRESHOLD'] 
        STATUS_CHECK_THRESHOLD = os.environ['STATUS_CHECK_THRESHOLD'] 
        TARGET_CONNECTION_ERROR_THRESHOLD = os.environ['TARGET_CONNECTION_ERROR_THRESHOLD'] 
        TARGET_RESPONSE_TIME_THRESHOLD = os.environ['TARGET_RESPONSE_TIME_THRESHOLD'] 
        HTTP_4XX_RESPONSE_THRESHOLD = os.environ['HTTP_4XX_RESPONSE_THRESHOLD']
        HTTP_5XX_RESPONSE_THRESHOLD = os.environ['HTTP_5XX_RESPONSE_THRESHOLD']
        RDS_CPU_UTILIZATION_CRITICAL_THRESHOLD = os.environ['RDS_CPU_UTILIZATION_CRITICAL_THRESHOLD'] 
        RDS_CPU_UTILIZATION_WARNING_THRESHOLD = os.environ['RDS_CPU_UTILIZATION_WARNING_THRESHOLD'] 
        RDS_FREESTORAGESPACE_WARNING_THRESHOLD = os.environ['RDS_FREESTORAGESPACE_WARNING_THRESHOLD']
        RDS_FREESTORAGESPACE_CRITICAL_THRESHOLD = os.environ['RDS_FREESTORAGESPACE_CRITICAL_THRESHOLD']
        RDS_FREEABLEMEM_WARNING_THRESHOLD = os.environ['RDS_FREEABLEMEM_WARNING_THRESHOLD']
        RDS_FREEABLEMEM_CRITICAL_THRESHOLD = os.environ['RDS_FREEABLEMEM_CRITICAL_THRESHOLD']
        codeBucketName = os.environ['codeBucketName']
        createAlarm = os.environ['createAlarm']

        # $$$$$$$$ to do : parametreize coma code bucket and key
    except:      
        print("FATAL ERROR. Lambda environment variables not set.")
        return "failed"
    try:
        bucket=codeBucketName
        key="input.csv"
        s3.meta.client.download_file(codeBucketName, 'input.csv', '/tmp/input.csv')
        print("file downloaded")
        reader = csv.reader(file('/tmp/input.csv'))
        print("file read")
        next(reader, None)
        print("file header skipped")
        data = list(reader)
        print(data)
    except:
        print("FATAL ERROR. unable to read file.")
        return "failed"


    validation_function_rds_ec2_elb(data)


    
    ################################################################################################ 
    #################################        IAM ROLE ARN        ###################################
    ################################################################################################ 
   
    response = iamClient.get_role(
        RoleName='lambda_alarm'
    )
    lambda_role=response['Role']['Arn']


    ################################################################################################ 
    ##############################        SNS TOPIC CREATION        ################################
    ################################################################################################ 
   
    lambdaClient.create_function(
        FunctionName='coma_create_sns_topic_lambda',
        Runtime='python2.7',
        Role=lambda_role,
        Handler='coma_create_sns_topic_lambda.lambda_handler',
        Code={
            'S3Bucket': codeBucketName,
            'S3Key': 'coma_create_sns_topic_lambda.zip'
        },
        Description='Function to create SNS topic for Alarms',
        Timeout=300,
        Environment={
            'Variables': {
                'EmailAddressStringList':EMAIL_ADDRESS_STRING_LIST,
                'TopicName':TOPIC_NAME
            }
        }
    )
    print("SNS topic function created")
    response = lambdaClient.invoke(FunctionName="coma_create_sns_topic_lambda",InvocationType='RequestResponse')
    warnTopicArn = response['Payload'].read().replace("\"","")

    lambdaClient.delete_function(
        FunctionName='coma_create_sns_topic_lambda'
    )


    ################################################################################################ 
    ##############################        EC2 ALARM CREATION        ################################
    ################################################################################################   

    if not EC2_ID_LIST or createAlarm == "NO":
        print("Skipping EC2 alarm creation")
    else:
        
      
        #############################################
        ## EC2 ALARM CREATION > 1.1 STATUS_CHECK_FAILED_INSTANCE
        #############################################
        print("Creating STATUS_CHECK_FAILED_INSTANCE ALARM..")
        lambdaClient.create_function(
            FunctionName='coma_ec2_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_ec2_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_ec2_alarm_lambda.zip'
            },
            Description='Function to create EC2 Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "InstanceIDs" : EC2_ID_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName":DASHBOARD_NAME+"/"+"STATUS_CHECK_FAILED_INSTANCE",
                    "AlarmDescription":"STATUS_CHECK_FAILED_INSTANCE is equal or above "+STATUS_CHECK_THRESHOLD,
                    "MetricName":"StatusCheckFailed_Instance",
                    "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                    "Threshold":STATUS_CHECK_THRESHOLD,
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Average",
                    "Unit":"Count",
                    "TreatMissingData":"breaching"
                }
            }
        )
        
        response = lambdaClient.invoke(FunctionName="coma_ec2_alarm_lambda",InvocationType='RequestResponse')
        print("STATUS_CHECK_FAILED_INSTANCE alarm function created.  ")
       

        lambdaClient.delete_function(
            FunctionName='coma_ec2_alarm_lambda'
        )

        #############################################
        ## EC2 ALARM CREATION > 1.1 STATUS_CHECK_FAILED_SYSTEM
        #############################################
        print("Creating STATUS_CHECK_FAILED_SYSTEM ALARM..")
        lambdaClient.create_function(
            FunctionName='coma_ec2_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_ec2_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_ec2_alarm_lambda.zip'
            },
            Description='Function to create EC2 Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "InstanceIDs" : EC2_ID_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"STATUS_CHECK_FAILED_SYSTEM",
                    "AlarmDescription":"STATUS_CHECK_FAILED_SYSTEM is equal or above "+STATUS_CHECK_THRESHOLD,
                    "MetricName":"StatusCheckFailed_System",
                    "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                    "Threshold":STATUS_CHECK_THRESHOLD,
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Average",
                    "Unit":"Count",
                    "TreatMissingData":"breaching"
                }
            }
        )
        response = lambdaClient.invoke(FunctionName="coma_ec2_alarm_lambda",InvocationType='RequestResponse')
        print("STATUS_CHECK_FAILED_SYSTEM alarm function created.  ")
       



        lambdaClient.delete_function(
            FunctionName='coma_ec2_alarm_lambda'
        )

        #############################################
        ## EC2 ALARM CREATION > CPU_UTILIZATION_CRITICAL
        #############################################
        print("Creating CPU_UTILIZATION_CRITICAL ALARM..")
        lambdaClient.create_function(
            FunctionName='coma_ec2_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_ec2_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_ec2_alarm_lambda.zip'
            },
            Description='Function to create EC2 Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "InstanceIDs" : EC2_ID_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"CPU_UTILIZATION_CRITICAL",
                    "AlarmDescription":"CPUUtilization is over "+CPU_UTILIZATION_CRITICAL_THRESHOLD+"%",
                    "MetricName":"CPUUtilization",
                    "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                    "Threshold":CPU_UTILIZATION_CRITICAL_THRESHOLD,
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Average",
                    "Unit":"Percent",
                    "TreatMissingData":"breaching"
                }
            }
        )
        response = lambdaClient.invoke(FunctionName="coma_ec2_alarm_lambda",InvocationType='RequestResponse')
        print("CPU_UTILIZATION_CRITICAL alarm function created.  ")
       

        lambdaClient.delete_function(
            FunctionName='coma_ec2_alarm_lambda'
        )

        #############################################
        ## EC2 ALARM CREATION > 1.2 CPU_UTILIZATION_WARNINGS
        #############################################
        print("Creating CPU_UTILIZATION_WARNINGS ALARM..")
        lambdaClient.create_function(
            FunctionName='coma_ec2_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_ec2_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_ec2_alarm_lambda.zip'
            },
            Description='Function to create EC2 Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "InstanceIDs" : EC2_ID_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"CPU_UTILIZATION_WARNING",
                    "AlarmDescription":"CPUUtilization is over "+CPU_UTILIZATION_WARNING_THRESHOLD+"%",
                    "MetricName":"CPUUtilization",
                    "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                    "Threshold":CPU_UTILIZATION_WARNING_THRESHOLD,
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Average",
                    "Unit":"Percent",
                    "TreatMissingData":"breaching"
                }
            }
        )
        response = lambdaClient.invoke(FunctionName="coma_ec2_alarm_lambda",InvocationType='RequestResponse')
        print("CPU_UTILIZATION_WARNING alarm function created.  ")
       

        lambdaClient.delete_function(
            FunctionName='coma_ec2_alarm_lambda'
        )

        if EC2_ID_LIST_WINDOW:
            #############################################
            ## EC2 ALARM CREATION > 1.3 MEMORY_UTILIZATION_WARNING
            #############################################
            print("Creating MEMORY_UTILIZATION_WARNING ALARM..")
            lambdaClient.create_function(
                FunctionName='coma_ec2_cloudwatchagent_alarm_lambda',
                Runtime='python2.7',
                Role=lambda_role,
                Handler='coma_ec2_cloudwatchagent_alarm_lambda.lambda_handler',
                Code={
                    'S3Bucket': codeBucketName,
                    'S3Key': 'coma_ec2_cloudwatchagent_alarm_lambda.zip'
                },
                Description='Function to create EC2 Alarms',
                Timeout=300,
                Environment={
                    'Variables': {
                        "InstanceIDs" : EC2_ID_LIST_WINDOWS_STRING,
                        "TopicARN" : warnTopicArn,
                        "AlarmName": DASHBOARD_NAME+"/"+"MEMORY_UTILIZATION_WARNING(Win)",
                        "AlarmDescription":"MEMORY_UTILIZATION is over "+MEMORY_UTILIZATION_WARNING_THRESHOLD_WIN+" GB",
                        "MetricName":"Memory Available Mbytes",
                        "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                        "Threshold":str(float(MEMORY_UTILIZATION_WARNING_THRESHOLD_WIN)*1024),
                        "Period":"300",
                        "EvaluationPeriods":"3",
                        "Statistic":"Average",
                        "Unit":"Megabytes",
                        "TreatMissingData":"breaching"
                    }
                }
            )
            response = lambdaClient.invoke(FunctionName="coma_ec2_cloudwatchagent_alarm_lambda",InvocationType='RequestResponse')
            print("MEMORY_UTILIZATION_WARNING alarm function created.  ")
           

            lambdaClient.delete_function(
                FunctionName='coma_ec2_cloudwatchagent_alarm_lambda'
            )

            #############################################
            ## EC2 ALARM CREATION > 1.4 MEMORY_UTILIZATION_CRITICAL
            #############################################
            print("Creating MEMORY_UTILIZATION_CRITICAL ALARM..")
            lambdaClient.create_function(
                FunctionName='coma_ec2_cloudwatchagent_alarm_lambda',
                Runtime='python2.7',
                Role=lambda_role,
                Handler='coma_ec2_cloudwatchagent_alarm_lambda.lambda_handler',
                Code={
                    'S3Bucket': codeBucketName,
                    'S3Key': 'coma_ec2_cloudwatchagent_alarm_lambda.zip'
                },
                Description='Function to create EC2 Alarms',
                Timeout=300,
                Environment={
                    'Variables': {
                        "InstanceIDs" : EC2_ID_LIST_WINDOWS_STRING,
                        "TopicARN" : warnTopicArn,
                        "AlarmName": DASHBOARD_NAME+"/"+"MEMORY_UTILIZATION_CRITICAL(Win)",
                        "AlarmDescription":"MEMORY_UTILIZATION is over "+MEMORY_UTILIZATION_CRITICAL_THRESHOLD_WIN+" GB",
                        "MetricName":"Memory Available Mbytes",
                        "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                        "Threshold":str(float(MEMORY_UTILIZATION_CRITICAL_THRESHOLD_WIN)*1024),
                        "Period":"300",
                        "EvaluationPeriods":"3",
                        "Statistic":"Average",
                        "Unit":"Megabytes",
                        "TreatMissingData":"breaching"
                    }
                }
            )
            response = lambdaClient.invoke(FunctionName="coma_ec2_cloudwatchagent_alarm_lambda",InvocationType='RequestResponse')
            print("MEMORY_UTILIZATION_CRITICAL alarm function created.  ")
           

            lambdaClient.delete_function(
                FunctionName='coma_ec2_cloudwatchagent_alarm_lambda'
            )


            #############################################
            ## EC2 ALARM CREATION > 1.5 DISK_UTILIZATION_WARNING
            #############################################
            print("Creating DISK_UTILIZATION_WARNING ALARM..")
            lambdaClient.create_function(
                FunctionName='coma_ec2_cloudwatchagent_alarm_lambda',
                Runtime='python2.7',
                Role=lambda_role,
                Handler='coma_ec2_cloudwatchagent_alarm_lambda.lambda_handler',
                Code={
                    'S3Bucket': codeBucketName,
                    'S3Key': 'coma_ec2_cloudwatchagent_alarm_lambda.zip'
                },
                Description='Function to create EC2 Alarms',
                Timeout=300,
                Environment={
                    'Variables': {
                        "InstanceIDs" : EC2_ID_LIST_WINDOWS_STRING,
                        "TopicARN" : warnTopicArn,
                        "AlarmName": DASHBOARD_NAME+"/"+"DISK_UTILIZATION_WARNING",
                        "AlarmDescription":"DISK_UTILIZATION is over "+DISK_UTILIZATION_WARNING_THRESHOLD+"%",
                        "MetricName":"LogicalDisk % Free Space",
                        "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                        "Threshold":DISK_UTILIZATION_WARNING_THRESHOLD,
                        "Period":"300",
                        "EvaluationPeriods":"3",
                        "Statistic":"Average",
                        "Unit":"Percent",
                        "TreatMissingData":"breaching"
                    }
                }
            )
            response = lambdaClient.invoke(FunctionName="coma_ec2_cloudwatchagent_alarm_lambda",InvocationType='RequestResponse')
            print("DISK_UTILIZATION_WARNING alarm function created.  ")
           

            lambdaClient.delete_function(
                FunctionName='coma_ec2_cloudwatchagent_alarm_lambda'
            )

            #############################################
            ## EC2 ALARM CREATION > 1.6 DISK_UTILIZATION_CRITICAL
            #############################################
            print("Creating DISK_UTILIZATION_CRITICAL ALARM..")
            lambdaClient.create_function(
                FunctionName='coma_ec2_cloudwatchagent_alarm_lambda',
                Runtime='python2.7',
                Role=lambda_role,
                Handler='coma_ec2_cloudwatchagent_alarm_lambda.lambda_handler',
                Code={
                    'S3Bucket': codeBucketName,
                    'S3Key': 'coma_ec2_cloudwatchagent_alarm_lambda.zip'
                },
                Description='Function to create EC2 Alarms',
                Timeout=300,
                Environment={
                    'Variables': {
                        "InstanceIDs" : EC2_ID_LIST_WINDOWS_STRING,
                        "TopicARN" : warnTopicArn,
                        "AlarmName": DASHBOARD_NAME+"/"+"DISK_UTILIZATION_CRITICAL",
                        "AlarmDescription":"DISK_UTILIZATION is over "+DISK_UTILIZATION_CRITICAL_THRESHOLD+"%",
                        "MetricName":"LogicalDisk % Free Space",
                        "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                        "Threshold":DISK_UTILIZATION_CRITICAL_THRESHOLD,
                        "Period":"300",
                        "EvaluationPeriods":"3",
                        "Statistic":"Average",
                        "Unit":"Percent",
                        "TreatMissingData":"breaching"
                    }
                }
            )
            response = lambdaClient.invoke(FunctionName="coma_ec2_cloudwatchagent_alarm_lambda",InvocationType='RequestResponse')
            print("DISK_UTILIZATION_CRITICAL alarm function created.  ")
           

            lambdaClient.delete_function(
                FunctionName='coma_ec2_cloudwatchagent_alarm_lambda'
            )

        if EC2_ID_LIST_LINUX:
                #############################################
                ## EC2 ALARM CREATION > 1.3 MEMORY_UTILIZATION_WARNING
                #############################################
                print("Creating MEMORY_UTILIZATION_WARNING ALARM..")
                lambdaClient.create_function(
                    FunctionName='coma_ec2_cloudwatchagent_alarm_lambda',
                    Runtime='python2.7',
                    Role=lambda_role,
                    Handler='coma_ec2_cloudwatchagent_alarm_lambda.lambda_handler',
                    Code={
                        'S3Bucket': codeBucketName,
                        'S3Key': 'coma_ec2_cloudwatchagent_alarm_lambda.zip'
                    },
                    Description='Function to create EC2 Alarms',
                    Timeout=300,
                    Environment={
                        'Variables': {
                            "InstanceIDs" : EC2_ID_LIST_LINUX_STRING,
                            "TopicARN" : warnTopicArn,
                            "AlarmName": DASHBOARD_NAME+"/"+"MEMORY_UTILIZATION_WARNING(Lin)",
                            "AlarmDescription":"MEMORY_UTILIZATION is over "+MEMORY_UTILIZATION_WARNING_THRESHOLD+"%",
                            "MetricName":"mem_used_percent",
                            "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                            "Threshold":MEMORY_UTILIZATION_WARNING_THRESHOLD,
                            "Period":"300",
                            "EvaluationPeriods":"3",
                            "Statistic":"Average",
                            "Unit":"Percent",
                            "TreatMissingData":"breaching"
                        }
                    }
                )
                response = lambdaClient.invoke(FunctionName="coma_ec2_cloudwatchagent_alarm_lambda",InvocationType='RequestResponse')
                print("MEMORY_UTILIZATION_WARNING alarm function created.  ")
               

                lambdaClient.delete_function(
                    FunctionName='coma_ec2_cloudwatchagent_alarm_lambda'
                )

                #############################################
                ## EC2 ALARM CREATION > 1.4 MEMORY_UTILIZATION_CRITICAL
                #############################################
                print("Creating MEMORY_UTILIZATION_CRITICAL ALARM..")
                lambdaClient.create_function(
                    FunctionName='coma_ec2_cloudwatchagent_alarm_lambda',
                    Runtime='python2.7',
                    Role=lambda_role,
                    Handler='coma_ec2_cloudwatchagent_alarm_lambda.lambda_handler',
                    Code={
                        'S3Bucket': codeBucketName,
                        'S3Key': 'coma_ec2_cloudwatchagent_alarm_lambda.zip'
                    },
                    Description='Function to create EC2 Alarms',
                    Timeout=300,
                    Environment={
                        'Variables': {
                            "InstanceIDs" : EC2_ID_LIST_LINUX_STRING,
                            "TopicARN" : warnTopicArn,
                            "AlarmName": DASHBOARD_NAME+"/"+"MEMORY_UTILIZATION_CRITICAL(Lin)",
                            "AlarmDescription":"MEMORY_UTILIZATION is over "+MEMORY_UTILIZATION_CRITICAL_THRESHOLD+"%",
                            "MetricName":"mem_used_percent",
                            "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                            "Threshold":MEMORY_UTILIZATION_CRITICAL_THRESHOLD,
                            "Period":"300",
                            "EvaluationPeriods":"3",
                            "Statistic":"Average",
                            "Unit":"Percent",
                            "TreatMissingData":"breaching"
                        }
                    }
                )
                response = lambdaClient.invoke(FunctionName="coma_ec2_cloudwatchagent_alarm_lambda",InvocationType='RequestResponse')
                print("MEMORY_UTILIZATION_CRITICAL alarm function created.  ")
               

                lambdaClient.delete_function(
                    FunctionName='coma_ec2_cloudwatchagent_alarm_lambda'
                )


                #############################################
                ## EC2 ALARM CREATION > 1.5 DISK_UTILIZATION_WARNING
                #############################################
                print("Creating DISK_UTILIZATION_WARNING ALARM..")
                lambdaClient.create_function(
                    FunctionName='coma_ec2_cloudwatchagent_alarm_lambda',
                    Runtime='python2.7',
                    Role=lambda_role,
                    Handler='coma_ec2_cloudwatchagent_alarm_lambda.lambda_handler',
                    Code={
                        'S3Bucket': codeBucketName,
                        'S3Key': 'coma_ec2_cloudwatchagent_alarm_lambda.zip'
                    },
                    Description='Function to create EC2 Alarms',
                    Timeout=300,
                    Environment={
                        'Variables': {
                            "InstanceIDs" : EC2_ID_LIST_LINUX_STRING,
                            "TopicARN" : warnTopicArn,
                            "AlarmName": DASHBOARD_NAME+"/"+"DISK_UTILIZATION_WARNING",
                            "AlarmDescription":"DISK_UTILIZATION is over "+DISK_UTILIZATION_WARNING_THRESHOLD+"%",
                            "MetricName":"disk_used_percent",
                            "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                            "Threshold":DISK_UTILIZATION_WARNING_THRESHOLD,
                            "Period":"300",
                            "EvaluationPeriods":"3",
                            "Statistic":"Average",
                            "Unit":"Percent",
                            "TreatMissingData":"breaching"
                        }
                    }
                )
                response = lambdaClient.invoke(FunctionName="coma_ec2_cloudwatchagent_alarm_lambda",InvocationType='RequestResponse')
                print("DISK_UTILIZATION_WARNING alarm function created.  ")
               

                lambdaClient.delete_function(
                    FunctionName='coma_ec2_cloudwatchagent_alarm_lambda'
                )

                #############################################
                ## EC2 ALARM CREATION > 1.6 DISK_UTILIZATION_CRITICAL
                #############################################
                print("Creating DISK_UTILIZATION_CRITICAL ALARM..")
                lambdaClient.create_function(
                    FunctionName='coma_ec2_cloudwatchagent_alarm_lambda',
                    Runtime='python2.7',
                    Role=lambda_role,
                    Handler='coma_ec2_cloudwatchagent_alarm_lambda.lambda_handler',
                    Code={
                        'S3Bucket': codeBucketName,
                        'S3Key': 'coma_ec2_cloudwatchagent_alarm_lambda.zip'
                    },
                    Description='Function to create EC2 Alarms',
                    Timeout=300,
                    Environment={
                        'Variables': {
                            "InstanceIDs" : EC2_ID_LIST_LINUX_STRING,
                            "TopicARN" : warnTopicArn,
                            "AlarmName": DASHBOARD_NAME+"/"+"DISK_UTILIZATION_CRITICAL",
                            "AlarmDescription":"DISK_UTILIZATION is over "+DISK_UTILIZATION_CRITICAL_THRESHOLD+"%",
                            "MetricName":"disk_used_percent",
                            "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                            "Threshold":DISK_UTILIZATION_CRITICAL_THRESHOLD,
                            "Period":"300",
                            "EvaluationPeriods":"3",
                            "Statistic":"Average",
                            "Unit":"Percent",
                            "TreatMissingData":"breaching"
                        }
                    }
                )
                response = lambdaClient.invoke(FunctionName="coma_ec2_cloudwatchagent_alarm_lambda",InvocationType='RequestResponse')
                print("DISK_UTILIZATION_CRITICAL alarm function created.  ")
               

                lambdaClient.delete_function(
                    FunctionName='coma_ec2_cloudwatchagent_alarm_lambda'
                )
    if not ELB_ARN_LIST or createAlarm == "NO":
        print("Skipping ELB alarm creation")
    else:
        ################################################################################################ 
        ##############################        ELB ALARM CREATION        ################################
        ################################################################################################   
      
        #############################################
        ## ELB ALARM CREATION > 2.1 UNHEALTHY_HOST_WARNINGS
        #############################################
        lambdaClient.create_function(
            FunctionName='coma_applicationelb_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_applicationelb_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_applicationelb_alarm_lambda.zip'
            },
            Description='Function to create ELB Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "appELBARNs" : ELB_ARN_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"UNHEALTHY_HOST_WARNING",
                    "AlarmDescription":"UNHEALTHY_HOST is equal or above "+UNHEALTHY_HOST_WARNING_THRESHOLD+" count",
                    "MetricName":"UnHealthyHostCount",
                    "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                    "Threshold":UNHEALTHY_HOST_WARNING_THRESHOLD,
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Average",
                    "Unit":"Count",
                    "TreatMissingData":"breaching"
                }
            }
        )
        print("UNHEALTHY_HOST_WARNING alarm function created")
        response = lambdaClient.invoke(FunctionName="coma_applicationelb_alarm_lambda",InvocationType='RequestResponse')


        lambdaClient.delete_function(
            FunctionName='coma_applicationelb_alarm_lambda'
        )

        #############################################
        ## ELB ALARM CREATION > 2.2 BACKEND_CONNECTION_ERROR_WARNING (TargetConnectionErrorCount)
        #############################################
        lambdaClient.create_function(
            FunctionName='coma_applicationelb_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_applicationelb_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_applicationelb_alarm_lambda.zip'
            },
            Description='Function to create ELB Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "appELBARNs" : ELB_ARN_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"BACKEND_CONNECTION_ERROR_WARNING",
                    "AlarmDescription":"TARGET_CONNECTION_ERROR is equal or above "+TARGET_CONNECTION_ERROR_THRESHOLD+" count",
                    "MetricName":"TargetConnectionErrorCount",
                    "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                    "Threshold":TARGET_CONNECTION_ERROR_THRESHOLD,
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Sum",
                    "Unit":"Count",
                    "TreatMissingData":"notBreaching"
                }
            }
        )
        print("BACKEND_CONNECTION_ERROR_WARNING alarm function created")
        response = lambdaClient.invoke(FunctionName="coma_applicationelb_alarm_lambda",InvocationType='RequestResponse')


        lambdaClient.delete_function(
            FunctionName='coma_applicationelb_alarm_lambda'
        )

        #############################################
        ## ELB ALARM CREATION > 2.3 TARGET_RESPONSE_TIME_WARNING
        #############################################
        lambdaClient.create_function(
            FunctionName='coma_applicationelb_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_applicationelb_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_applicationelb_alarm_lambda.zip'
            },
            Description='Function to create ELB Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "appELBARNs" : ELB_ARN_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"TARGET_RESPONSE_TIME_WARNING",
                    "AlarmDescription":"TARGET_RESPONSE_TIME is equal or above "+TARGET_RESPONSE_TIME_THRESHOLD+" ms",
                    "MetricName":"TargetResponseTime",
                    "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                    "Threshold": str(float(TARGET_RESPONSE_TIME_THRESHOLD)/1000),
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Average",
                    "Unit":"Seconds",
                    "TreatMissingData":"breaching"
                }
            }
        )
        print("TARGET_RESPONSE_TIME_WARNING alarm function created")
        response = lambdaClient.invoke(FunctionName="coma_applicationelb_alarm_lambda",InvocationType='RequestResponse')


        lambdaClient.delete_function(
            FunctionName='coma_applicationelb_alarm_lambda'
        )

        #############################################
        ## ELB ALARM CREATION > 2.4 HTTP_4XX_RESPONSE_WARNING
        #############################################
        lambdaClient.create_function(
            FunctionName='coma_applicationelb_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_applicationelb_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_applicationelb_alarm_lambda.zip'
            },
            Description='Function to create ELB Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "appELBARNs" : ELB_ARN_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"HTTP_4XX_RESPONSE_WARNING",
                    "AlarmDescription":"HTTP_4XX_RESPONSE is equal or above "+HTTP_4XX_RESPONSE_THRESHOLD+" count",
                    "MetricName":"HTTPCode_Target_4XX_Count",
                    "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                    "Threshold":HTTP_4XX_RESPONSE_THRESHOLD,
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Sum",
                    "Unit":"Count",
                    "TreatMissingData":"notBreaching"
                }
            }
        )
        print("HTTP_4XX_RESPONSE_WARNING alarm function created")
        response = lambdaClient.invoke(FunctionName="coma_applicationelb_alarm_lambda",InvocationType='RequestResponse')


        lambdaClient.delete_function(
            FunctionName='coma_applicationelb_alarm_lambda'
        )       

        #############################################
        ## ELB ALARM CREATION > 2.5 HTTP_5XX_RESPONSE_WARNING
        #############################################
        lambdaClient.create_function(
            FunctionName='coma_applicationelb_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_applicationelb_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_applicationelb_alarm_lambda.zip'
            },
            Description='Function to create ELB Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "appELBARNs" : ELB_ARN_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"HTTP_5XX_RESPONSE_WARNING",
                    "AlarmDescription":"HTTP_5XX_RESPONSE is equal or above "+HTTP_5XX_RESPONSE_THRESHOLD+" count",
                    "MetricName":"HTTPCode_Target_5XX_Count",
                    "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                    "Threshold":HTTP_5XX_RESPONSE_THRESHOLD,
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Sum",
                    "Unit":"Count",
                    "TreatMissingData":"notBreaching" 
                }
            }
        )
        print("HTTP_5XX_RESPONSE_WARNING alarm function created")
        response = lambdaClient.invoke(FunctionName="coma_applicationelb_alarm_lambda",InvocationType='RequestResponse')


        lambdaClient.delete_function(
            FunctionName='coma_applicationelb_alarm_lambda'
        )       

    if not RDS_IDENTIFIER_LIST or createAlarm == "NO":
        print("Skipping RDS alarm creation")
    else:
        ################################################################################################ 
        ##############################        RDS ALARM CREATION        ################################
        ################################################################################################   
      
        #############################################
        ## RDS ALARM CREATION > 3.1 RDS_CPU_UTILIZATION_WARNING 
        #############################################
        lambdaClient.create_function(
            FunctionName='coma_rds_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_rds_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_rds_alarm_lambda.zip'
            },
            Description='Function to create RDS Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "DBInstanceIdentifiers" : RDS_IDENTIFIER_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"RDS_CPU_UTILIZATION_WARNING",
                    "AlarmDescription":"RDS_CPU_UTILIZATION_WARNING is equal or above "+RDS_CPU_UTILIZATION_WARNING_THRESHOLD+"%",
                    "MetricName":"CPUUtilization",
                    "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                    "Threshold":RDS_CPU_UTILIZATION_WARNING_THRESHOLD,
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Average",
                    "Unit":"Percent",
                    "TreatMissingData":"breaching"
                }
            }
        )
        print("RDS_CPU_UTILIZATION_WARNING alarm function created")
        response = lambdaClient.invoke(FunctionName="coma_rds_alarm_lambda",InvocationType='RequestResponse')


        lambdaClient.delete_function(
            FunctionName='coma_rds_alarm_lambda'
        )

        #############################################
        ## RDS ALARM CREATION > 3.2 RDS_CPU_UTILIZATION_CRITICAL 
        #############################################
        lambdaClient.create_function(
            FunctionName='coma_rds_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_rds_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_rds_alarm_lambda.zip'
            },
            Description='Function to create RDS Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "DBInstanceIdentifiers" : RDS_IDENTIFIER_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"RDS_CPU_UTILIZATION_CRITICAL",
                    "AlarmDescription":"RDS_CPU_UTILIZATION_CRITICAL is equal or above "+RDS_CPU_UTILIZATION_CRITICAL_THRESHOLD+"%",
                    "MetricName":"CPUUtilization",
                    "ComparisonOperator":"GreaterThanOrEqualToThreshold",
                    "Threshold":RDS_CPU_UTILIZATION_CRITICAL_THRESHOLD,
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Average",
                    "Unit":"Percent",
                    "TreatMissingData":"breaching"
                }
            }
        )
        print("RDS_CPU_UTILIZATION_CRITICAL alarm function created")
        response = lambdaClient.invoke(FunctionName="coma_rds_alarm_lambda",InvocationType='RequestResponse')


        lambdaClient.delete_function(
            FunctionName='coma_rds_alarm_lambda'
        )


        #############################################
        ## RDS ALARM CREATION > 3.3 RDS_FREESTORAGESPACE_WARNING
        #############################################
        lambdaClient.create_function(
            FunctionName='coma_rds_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_rds_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_rds_alarm_lambda.zip'
            },
            Description='Function to create RDS Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "DBInstanceIdentifiers" : RDS_IDENTIFIER_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"RDS_FREESTORAGESPACE_WARNING",
                    "AlarmDescription":"RDS_FREESTORAGESPACE_WARNING is equal or above "+RDS_FREESTORAGESPACE_WARNING_THRESHOLD+" GB",
                    "MetricName":"FreeStorageSpace",
                    "ComparisonOperator":"LessThanOrEqualToThreshold",
                    "Threshold":str(float(RDS_FREESTORAGESPACE_WARNING_THRESHOLD)*1073741824),
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Average",
                    "Unit":"Bytes",
                    "TreatMissingData":"breaching"
                }
            }
        )
        print("RDS_FREESTORAGESPACE_WARNING alarm function created")
        response = lambdaClient.invoke(FunctionName="coma_rds_alarm_lambda",InvocationType='RequestResponse')


        lambdaClient.delete_function(
            FunctionName='coma_rds_alarm_lambda'
        )


        #############################################
        ## RDS ALARM CREATION > 3.4 RDS_FREESTORAGESPACE_CRITICAL 
        #############################################
        lambdaClient.create_function(
            FunctionName='coma_rds_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_rds_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_rds_alarm_lambda.zip'
            },
            Description='Function to create RDS Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "DBInstanceIdentifiers" : RDS_IDENTIFIER_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"RDS_FREESTORAGESPACE_CRITICAL",
                    "AlarmDescription":"RDS_FREESTORAGESPACE_CRITICAL is equal or above "+RDS_FREESTORAGESPACE_CRITICAL_THRESHOLD+" GB",
                    "MetricName":"FreeStorageSpace",
                    "ComparisonOperator":"LessThanOrEqualToThreshold",
                    "Threshold":str(float(RDS_FREESTORAGESPACE_CRITICAL_THRESHOLD)*1073741824),
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Average",
                    "Unit":"Bytes",
                    "TreatMissingData":"breaching"
                }
            }
        )
        print("RDS_FREESTORAGESPACE_CRITICAL alarm function created")
        response = lambdaClient.invoke(FunctionName="coma_rds_alarm_lambda",InvocationType='RequestResponse')


        lambdaClient.delete_function(
            FunctionName='coma_rds_alarm_lambda'
        )


        #############################################
        ## ELB ALARM CREATION > 3.5 RDS_FREEABLEMEM_WARNING
        #############################################
        lambdaClient.create_function(
            FunctionName='coma_rds_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_rds_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_rds_alarm_lambda.zip'
            },
            Description='Function to create RDS Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "DBInstanceIdentifiers" : RDS_IDENTIFIER_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"RDS_FREEABLEMEM_WARNING",
                    "AlarmDescription":"RDS_FREEABLEMEM_WARNING is equal or above "+RDS_FREEABLEMEM_WARNING_THRESHOLD+" GB",
                    "MetricName":"FreeableMemory",
                    "ComparisonOperator":"LessThanOrEqualToThreshold",
                    "Threshold":str(float(RDS_FREEABLEMEM_WARNING_THRESHOLD)*1073741824),
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Average",
                    "Unit":"Bytes",
                    "TreatMissingData":"breaching"
                }
            }
        )
        print("RDS_FREEABLEMEM_WARNING alarm function created")
        response = lambdaClient.invoke(FunctionName="coma_rds_alarm_lambda",InvocationType='RequestResponse')


        lambdaClient.delete_function(
            FunctionName='coma_rds_alarm_lambda'
        )       

        #############################################
        ## RDS ALARM CREATION > 3.6 RDS_FREEABLEMEM_CRITICAL 
        #############################################
        lambdaClient.create_function(
            FunctionName='coma_rds_alarm_lambda',
            Runtime='python2.7',
            Role=lambda_role,
            Handler='coma_rds_alarm_lambda.lambda_handler',
            Code={
                'S3Bucket': codeBucketName,
                'S3Key': 'coma_rds_alarm_lambda.zip'
            },
            Description='Function to create RDS Alarms',
            Timeout=300,
            Environment={
                'Variables': {
                    "DBInstanceIdentifiers" : RDS_IDENTIFIER_LIST_STRING,
                    "TopicARN" : warnTopicArn,
                    "AlarmName": DASHBOARD_NAME+"/"+"RDS_FREEABLEMEM_CRITICAL",
                    "AlarmDescription":"RDS_FREEABLEMEM_CRITICAL is equal or above "+RDS_FREEABLEMEM_CRITICAL_THRESHOLD+" GB",
                    "MetricName":"FreeableMemory",
                    "ComparisonOperator":"LessThanOrEqualToThreshold",
                    "Threshold":str(float(RDS_FREEABLEMEM_CRITICAL_THRESHOLD)*1073741824),
                    "Period":"300",
                    "EvaluationPeriods":"3",
                    "Statistic":"Average",
                    "Unit":"Bytes",
                    "TreatMissingData":"breaching"
                }
            }
        )
        print("RDS_FREEABLEMEM_CRITICAL alarm function created")
        response = lambdaClient.invoke(FunctionName="coma_rds_alarm_lambda",InvocationType='RequestResponse')


        lambdaClient.delete_function(
            FunctionName='coma_rds_alarm_lambda'
        )


    





    ################################################################################################ 
    ##############################        DASHBOARD CREATION        ################################
    ################################################################################################ 
    widgets       = []
    widget = []
    X=0
    Y=0

    widget = {
                    "type": "text",
                    "x": X,
                    "y": Y,
                    "width": 24,
                    "height": 1,
                    "properties": {
                        "markdown": "\n# **MONITORING DASHBOARD : "+DASHBOARD_NAME+"**\n"
                    }
                }
    widgets.append(widget)
    Y=Y+1


    for ec2dns, ec2value in EC2_INVENTORY_DICT.iteritems():
        ##########################################################################################
        ## Widget for EC2 >
        ##########################################################################################
        widget = {
                    "type": "text",
                    "x": X,
                    "y": Y,
                    "width": 24,
                    "height": 2,
                    "properties": {
                        "markdown": "## **Metrics for EC2 : "+ec2dns+"**\n### EC2 id: "+ec2value[0]
                    }
                }
        widgets.append(widget)
        Y=Y+2
        #############################################
        ## Widget for EC2 > Status Check Failed
        #############################################
        metrics = []
        #for ec2id in EC2_ID_LIST:
        metrics.append(["AWS/EC2", "StatusCheckFailed_Instance", "InstanceId", ec2value[0], { "label": "Instance Status"}])
        metrics.append(["AWS/EC2", "StatusCheckFailed_System", "InstanceId", ec2value[0] , { "label": "System Status"}])
        #print(metrics)
        widget = {
            "type": "metric",
            "x": 0,
            "y": Y,
            "width": 24,
            "height": 6,
            "properties": {
                "view": "timeSeries",
                "metrics": metrics,
                "region": "us-east-1",
                "title": "### Status Check Failed",
                "period": 300,
                "stat":"Average",
                "annotations": {
                    "horizontal": [
                        {
                            "color": "#ff0000",
                            "label": "Critical",
                            "value": float(STATUS_CHECK_THRESHOLD)
                        }
                    ]
                }
            }
        }                       
        widgets.append(widget)
        Y=Y+3

        #############################################
        ## Widget for EC2 > CPU Utilization
        #############################################
        metrics = []
        #for ec2id in EC2_ID_LIST:
        metrics.append(["AWS/EC2", "CPUUtilization", "InstanceId", ec2value[0], { "label": ec2value[0] }])
        
        widget =  {
            "type": "metric",
            "x": 0,
            "y": Y,
            "width": 12,
            "height": 6,
            "properties": {
                "view": "timeSeries",
                "metrics": metrics,
                "region": "us-east-1",
                "title": "### CPU Utilization",
                "stat":"Average",
                "annotations": {
                    "horizontal": [
                        {
                            "color": "#ff0000",
                            "label": "Critical",
                            "value": float(CPU_UTILIZATION_CRITICAL_THRESHOLD)
                        },
                        {
                            "color": "#FFA500",
                            "label": "Warning",
                            "value": float(CPU_UTILIZATION_WARNING_THRESHOLD)
                        }
                    ]
                },
                "yAxis": {
                  "left": {
                    "min": 0,
                    "max": 100
                  }
                }
            }
        }
        widgets.append(widget)
        
        #############################################
        ## Widget for EC2 > Network In and Out
        #############################################
        metrics = []
        #for ec2id in EC2_ID_LIST:
        metrics.append(["AWS/EC2", "NetworkIn", "InstanceId", ec2value[0], { "label": "NetworkIn" }])
        metrics.append(["AWS/EC2", "NetworkOut", "InstanceId", ec2value[0], { "label": "NetworkOut" }])
        
        widget =  {
            "type": "metric",
            "x": 12,
            "y": Y,
            "width": 12,
            "height": 6,
            "stat":"Average",
            "properties": {
                "view": "timeSeries",
                "metrics": metrics,
                "region": "us-east-1",
                "title": "### Network In/Out",
            }
        }
        widgets.append(widget)
        Y=Y+6

        #############################################
        ## Widget for EC2 > Disk
        #############################################
        metrics = []
        #for ec2id in EC2_ID_LIST:
        if ec2value[1]=="Linux":
            metrics.append(["CWAgent", "disk_used_percent", "InstanceId", ec2value[0], { "label": ec2value[0] }])
        elif ec2value[1]=="Windows":
            metrics.append(["CWAgent", "LogicalDisk % Free Space", "InstanceId", ec2value[0], { "label": ec2value[0] }])
        
        widget =  {
            "type": "metric",
            "x": 0,
            "y": Y,
            "width": 12,
            "height": 6,
            "stat":"Average",
            "properties": {
                "view": "timeSeries",
                "metrics": metrics,
                "region": "us-east-1",
                "title": "### Disk Utilization",
                "annotations": {
                    "horizontal": [
                        {
                            "color": "#ff0000",
                            "label": "Critical",
                            "value": float(DISK_UTILIZATION_CRITICAL_THRESHOLD)
                        },
                        {
                            "color": "#FFA500",
                            "label": "Warning",
                            "value": float(DISK_UTILIZATION_WARNING_THRESHOLD)
                        }
                    ]
                },
                "yAxis": {
                  "left": {
                    "min": 0,
                    "max": 100
                  }
                }
            }
        }
        widgets.append(widget)

        #############################################
        ## Widget for EC2 > Memory
        #############################################
        metrics = []
        #for ec2id in EC2_ID_LIST:
        #metrics.append(["CWAgent", "mem_used_percent", "InstanceId", ec2value[0], { "label": "Memory" }])
        if ec2value[1]=="Linux":
            metrics.append(["CWAgent", "mem_used_percent", "InstanceId", ec2value[0], { "label": ec2value[0] }])
            widget =  {
                "type": "metric",
                "x": 12,
                "y": Y,
                "width": 12,
                "height": 6,
                "stat":"Average",
                "properties": {
                    "view": "timeSeries",
                    "metrics": metrics,
                    "region": "us-east-1",
                    "title": "### Memory Utilization",
                    "annotations": {
                        "horizontal": [
                            {
                                "color": "#ff0000",
                                "label": "Critical",
                                "value": float(MEMORY_UTILIZATION_CRITICAL_THRESHOLD)
                            },
                            {
                                "color": "#FFA500",
                                "label": "Warning",
                                "value": float(MEMORY_UTILIZATION_WARNING_THRESHOLD)
                            }
                        ]
                    },
                    "yAxis": {
                      "left": {
                        "min": 0,
                        "max": 100
                      }
                    }
                }
            }
        elif ec2value[1]=="Windows":
            metrics.append(["CWAgent", "Memory Available Mbytes", "InstanceId", ec2value[0], { "label": ec2value[0] }])
            widget =  {
            "type": "metric",
            "x": 12,
            "y": Y,
            "width": 12,
            "height": 6,
            "stat":"Average",
            "properties": {
                "view": "timeSeries",
                "metrics": metrics,
                "region": "us-east-1",
                "title": "### Memory Utilization",
                "annotations": {
                    "horizontal": [
                        {
                            "color": "#ff0000",
                            "label": "Critical "+MEMORY_UTILIZATION_CRITICAL_THRESHOLD_WIN+" GB",
                            "value": float(MEMORY_UTILIZATION_CRITICAL_THRESHOLD_WIN)*1024
                        },
                        {
                            "color": "#FFA500",
                            "label": "Warning "+MEMORY_UTILIZATION_WARNING_THRESHOLD_WIN+" GB",
                            "value": float(MEMORY_UTILIZATION_WARNING_THRESHOLD_WIN)*1024
                        }
                    ]
                },
                "yAxis": {
                  "left": {
                    "min": 0,
                    "max": 1.43*float(MEMORY_UTILIZATION_WARNING_THRESHOLD_WIN)*1024
                  }
                }
            }
        }
        
        
        
        widgets.append(widget)
        Y=Y+6

    ##########################################################################################
    ## Widget for ELB >
    ##########################################################################################
    for key_dns, value_arn_dict in APP_ELB_INVENTORY_DICT.iteritems():## For every LB DNS
        for key_arn, value_tg_list in value_arn_dict.iteritems():## For every ARN
            LoadBalancer=key_arn.split(":loadbalancer/")[1]
            for tg in value_tg_list:## For every Target group
                TargetGroupList=[]
                TargetGroupList.append("targetgroup"+tg.split(":targetgroup")[1])

            LoadBalancerName=LoadBalancer.split("/")[1]
            widget = {
                        "type": "text",
                        "x": 0,
                        "y": Y,
                        "width": 24,
                        "height": 2,
                        "properties": {
                            "markdown": "## **Metrics for ELB : "+key_dns+"**\n### Loadbalancer name : "+LoadBalancerName
                        }
                    }
        

            widgets.append(widget)
            Y=Y+2

            #############################################
            ## Widget for ELB > HOST_HEALTH_COUNT
            #############################################
            metrics = []
            #for i in range(len(LBNamesWithTarget)):
            for TargetGroup in TargetGroupList:
                metrics.append(["AWS/ApplicationELB", "UnHealthyHostCount", "TargetGroup", TargetGroup, "LoadBalancer", LoadBalancer, { "label": "UnHealthyHostCount-"+TargetGroup }])
                metrics.append(["AWS/ApplicationELB", "HealthyHostCount", "TargetGroup", TargetGroup, "LoadBalancer", LoadBalancer, { "label": "HealthyHostCount-"+TargetGroup }])

            widget = {
                "type": "metric",
                "x": 0,
                "y": Y,
                "width": 12,
                "height": 3,
                "stat":"Min",
                "properties": {
                    "view": "singleValue",
                    "metrics": metrics,
                    "region": "us-east-1",
                    "title": "Host Health Count",
                    "period": 300
                }
            }             
        
            widgets.append(widget)

            #############################################
            ## Widget for ELB > REQUEST_COUNTS
            #############################################
            metrics = []
            #for i in range(len(LBNamesWithTarget)):
            metrics.append(["AWS/ApplicationELB", "RequestCount", "LoadBalancer", LoadBalancer, { "label": "RequestCount" }])
            metrics.append(["AWS/ApplicationELB", "NewConnectionCount", "LoadBalancer", LoadBalancer, { "label": "NewConnectionCount" }])

            widget = {
                "type": "metric",
                "x": 12,
                "y": Y,
                "width": 12,
                "height": 3,
                "stat":"Min",
                "properties": {
                    "view": "singleValue",
                    "metrics": metrics,
                    "region": "us-east-1",
                    "title": "Request and New Connection Count",
                    "period": 300
                }
            }             
        
            widgets.append(widget)
            Y=Y+3


            #############################################
            ## Widget for ELB > TargetConnectionErrorCount
            #############################################
            metrics = []
            #for i in range(len(LBNamesWithTarget)):
            metrics.append(["AWS/ApplicationELB", "TargetConnectionErrorCount", "LoadBalancer", LoadBalancer, { "label": LoadBalancerName }])
            #print(metrics)

            widget = {
                "type": "metric",
                "x": 0,
                "y": Y,
                "width": 12,
                "height": 6,
                "properties": {
                    "view": "timeSeries",
                    "metrics": metrics,
                    "region": "us-east-1",
                    "title": "Target Connection Error Count",
                    "period": 300,
                    "stat":"Sum",
                    "annotations": {
                        "horizontal": [
                            {
                                "color": "#FFA500",
                                "label": "Warning",
                                "value": float(TARGET_CONNECTION_ERROR_THRESHOLD)
                            }
                        ]
                    }
                }
            }   
            widgets.append(widget)


            #############################################
            ## Widget for ELB > TargetResponseTime
            #############################################
            metrics = []
            #for i in range(len(LBNamesWithTarget)):
            metrics.append(["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", LoadBalancer, { "label": LoadBalancerName }])
            #print(metrics)

            widget = {
                "type": "metric",
                "x": 12,
                "y": Y,
                "width": 12,
                "height": 6,
                "properties": {
                    "view": "timeSeries",
                    "metrics": metrics,
                    "region": "us-east-1",
                    "title": "Target Response Time",
                    "period": 300,
                    "stat":"Average",
                    "annotations": {
                        "horizontal": [
                            {
                                "color": "#FFA500",
                                "label": "Warning",
                                "value": float(TARGET_RESPONSE_TIME_THRESHOLD)/1000
                            }
                        ]
                    }
                }
            } 
            widgets.append(widget)
            Y=Y+3

            #############################################
            ## Widget for ELB > Target Error Count
            #############################################
            metrics = []
            #for i in range(len(LBNamesWithTarget)):
            metrics.append(["AWS/ApplicationELB", "HTTPCode_Target_3XX_Count", "LoadBalancer", LoadBalancer, { "label": "HTTPCode_Target_3XX_Count" }])
            metrics.append(["AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "LoadBalancer", LoadBalancer, { "label": "HTTPCode_Target_4XX_Count" }])
            metrics.append(["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", LoadBalancer, { "label": "HTTPCode_Target_5XX_Count" }])
            #print(metrics)

            widget = {
                "type": "metric",
                "x": 0,
                "y": Y,
                "width": 12,
                "height": 6,
                "properties": {
                    "view": "timeSeries",
                    "metrics": metrics,
                    "region": "us-east-1",
                    "title": "Target Error Count",
                    "period": 300,
                    "stat":"Sum",
                    "annotations": {
                        "horizontal": [
                            {
                                "color": "#FFA500",
                                "label": "HTTP_4XX",
                                "value": float(HTTP_4XX_RESPONSE_THRESHOLD)
                            },
                            {
                                "color": "#FFA500",
                                "label": "                      HTTP_5XX",
                                "value": float(HTTP_5XX_RESPONSE_THRESHOLD)
                            }
                        ]
                    }
                }
            } 
            
            widgets.append(widget)
            
            #############################################
            ## Widget for ELB > ELB Error Count
            #############################################
            metrics = []
            #for i in range(len(LBNamesWithTarget)):
            metrics.append(["AWS/ApplicationELB", "HTTPCode_ELB_4XX_Count", "LoadBalancer", LoadBalancer, { "label": "HTTPCode_ELB_4XX_Count" }])
            metrics.append(["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", LoadBalancer, { "label": "HTTPCode_ELB_5XX_Count" }])

            widget = {
                "type": "metric",
                "x": 12,
                "y": Y,
                "width": 12,
                "height": 6,
                "properties": {
                    "view": "timeSeries",
                    "metrics": metrics,
                    "region": "us-east-1",
                    "title": "ELB Error Count",
                    "period": 300,
                    "stat":"Sum"
                }
            }
            widgets.append(widget)
            Y=Y+3


    ##########################################################################################
    ## Widget for RDS >
    ##########################################################################################
    for rdsendpoint, rdsid in RDS_INVENTORY_DICT.iteritems():
        widget = {
                    "type": "text",
                    "x": 0,
                    "y": Y,
                    "width": 24,
                    "height": 1,
                    "properties": {
                        "markdown": "\n## **Metrics for RDS : "+rdsendpoint+"**\n"
                    }
                }
        widgets.append(widget)
        Y=Y+1

        #############################################
        ## Widget for RDS > CPU Utilization
        #############################################
        metrics = []
        #for ec2id in EC2_ID_LIST:
        metrics.append(["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", rdsid, { "label": rdsid }])
        
        widget =  {
            "type": "metric",
            "x": 0,
            "y": Y,
            "width": 12,
            "height": 6,
            "properties": {
                "view": "timeSeries",
                "metrics": metrics,
                "region": "us-east-1",
                "title": "### CPU Utilization",
                "stat":"Average",
                "annotations": {
                    "horizontal": [
                        {
                            "color": "#ff0000",
                            "label": "Critical",
                            "value": float(RDS_CPU_UTILIZATION_CRITICAL_THRESHOLD)
                        },
                        {
                            "color": "#FFA500",
                            "label": "Warning",
                            "value": float(RDS_CPU_UTILIZATION_WARNING_THRESHOLD)
                        }
                    ]
                },
                "yAxis": {
                  "left": {
                    "min": 0,
                    "max": 100
                  }
                }
            }
        }
        widgets.append(widget)


        #############################################
        ## Widget for RDS > FreeableMemory
        #############################################
        metrics = []
        #for ec2id in EC2_ID_LIST:
        metrics.append(["AWS/RDS", "FreeableMemory", "DBInstanceIdentifier", rdsid, { "label": rdsid }])
        
        widget =  {
            "type": "metric",
            "x": 12,
            "y": Y,
            "width": 12,
            "height": 6,
            "properties": {
                "view": "timeSeries",
                "stacked": False,
                "metrics": metrics,
                "region": "us-east-1",
                "title": "### FreeableMemory",
                "stat":"Average",
                "annotations": {
                    "horizontal": [
                        {
                            "color": "#ff7f0e",
                            "label": "Warning "+RDS_FREEABLEMEM_WARNING_THRESHOLD+" GB",
                            "value": float(RDS_FREEABLEMEM_WARNING_THRESHOLD)*1073741824
                        },
                        {
                            "color": "#d62728",
                            "label": "Critical "+RDS_FREEABLEMEM_CRITICAL_THRESHOLD+" GB",
                            "value": float(RDS_FREEABLEMEM_CRITICAL_THRESHOLD)*1073741824
                        }
                    ]
                },
                "yAxis": {
                  "left": {
                    "min": 0,
                    "max": 1.43*float(RDS_FREEABLEMEM_WARNING_THRESHOLD)*1073741824
                  }
                }
            }
        }
        widgets.append(widget)
        Y=Y+6

        #############################################
        ## Widget for RDS > Database Connections
        #############################################
        metrics = []
        #for ec2id in EC2_ID_LIST:
        metrics.append(["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", rdsid, { "label": rdsid }])
        
        widget =  {
            "type": "metric",
            "x": 0,
            "y": Y,
            "width": 12,
            "height": 6,
            "properties": {
                "view": "timeSeries",
                "stacked": False,
                "metrics": metrics,
                "region": "us-east-1",
                "stat":"Average",
                "title": "### DatabaseConnections"
            }
        }
        widgets.append(widget)

        #############################################
        ## Widget for RDS > Latency
        #############################################
        metrics = []
        #for ec2id in EC2_ID_LIST:
        metrics.append(["AWS/RDS", "ReadLatency", "DBInstanceIdentifier", rdsid, { "label": "ReadLatency" }])
        metrics.append(["AWS/RDS", "WriteLatency", "DBInstanceIdentifier", rdsid, { "label": "WriteLatency" }])
        
        widget =  {
            "type": "metric",
            "x": 12,
            "y": Y,
            "width": 12,
            "height": 6,
            "properties": {
                "view": "timeSeries",
                "stacked": True,
                "metrics": metrics,
                "region": "us-east-1",
                "stat":"Average",
                "title": "### Latency"
            }
        }
        widgets.append(widget)
        Y=Y+12


        #############################################
        ## Widget for RDS > Free Storage
        #############################################
        metrics = []
        #for ec2id in EC2_ID_LIST:
        metrics.append(["AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier", rdsid, { "label": rdsid }])
        
        widget =  {
            "type": "metric",
            "x": 0,
            "y": Y,
            "width": 12,
            "height": 6,
            "properties": {
                "view": "timeSeries",
                "stacked": False,
                "metrics": metrics,
                "stat":"Average",
                "region": "us-east-1",
                "title": "### FreeStorageSpace",
                "annotations": {
                    "horizontal": [
                        {
                            "color": "#ff7f0e",
                            "label": "Warning "+RDS_FREESTORAGESPACE_WARNING_THRESHOLD+" GB",
                            "value":  float(RDS_FREESTORAGESPACE_WARNING_THRESHOLD)*1073741824
                        },
                        {
                            "color": "#d62728",
                            "label": "Critical "+RDS_FREESTORAGESPACE_CRITICAL_THRESHOLD+" GB",
                            "value": float(RDS_FREESTORAGESPACE_CRITICAL_THRESHOLD)*1073741824
                        }
                    ]
                },
                "yAxis": {
                  "left": {
                    "min": 0,
                    "max": 1.43*float(RDS_FREESTORAGESPACE_WARNING_THRESHOLD)*1073741824
                  }
                }
            }
        }
        widgets.append(widget)


        #############################################
        ## Widget for RDS > Throughput
        #############################################
        metrics = []
        #for ec2id in EC2_ID_LIST:
        metrics.append(["AWS/RDS", "ReadThroughput", "DBInstanceIdentifier", rdsid, { "label": "ReadThroughput" }])
        metrics.append(["AWS/RDS", "WriteThroughput", "DBInstanceIdentifier", rdsid, { "label": "WriteThroughput" }])
        
        widget =  {
            "type": "metric",
            "x": 12,
            "y": Y,
            "width": 12,
            "height": 6,
            "properties": {
                "view": "timeSeries",
                "stacked": True,
                "stat":"Average",
                "metrics": metrics,
                "region": "us-east-1",
                "title": "### Throughput"
            }
        }
        widgets.append(widget)
        Y=Y+6


        #############################################
        ## Widget for RDS > Read IOPS
        #############################################
        metrics = []
        #for ec2id in EC2_ID_LIST:
        metrics.append(["AWS/RDS", "ReadIOPS", "DBInstanceIdentifier", rdsid, { "label": "ReadIOPS" }])
        
        widget =  {
            "type": "metric",
            "x": 0,
            "y": Y,
            "width": 12,
            "height": 6,
            "properties": {
                "view": "timeSeries",
                "stacked": False,
                "stat":"Average",
                "metrics": metrics,
                "region": "us-east-1",
                "title": "### ReadIOPS"
            }
        }
        widgets.append(widget)

        #############################################
        ## Widget for RDS > Write IOPS
        #############################################
        metrics = []
        #for ec2id in EC2_ID_LIST:
        metrics.append(["AWS/RDS", "WriteIOPS", "DBInstanceIdentifier", rdsid, { "label": "WriteIOPS" }])
        
        widget =  {
            "type": "metric",
            "x": 12,
            "y": Y,
            "width": 12,
            "height": 6,
            "properties": {
                "view": "timeSeries",
                "stacked": False,
                "stat":"Average",
                "metrics": metrics,
                "region": "us-east-1",
                "title": "### WriteIOPS"
            }
        }
        widgets.append(widget)


    body   = {'widgets' : widgets}
    body_j = json.dumps(body)
    
    #print(widgets)
    cw.put_dashboard(DashboardName = DASHBOARD_NAME,DashboardBody = body_j)
    print("DASHBOARD "+DASHBOARD_NAME+" CREATED")


    send_response(event, context, responseStatus, responseData)

    #responseData = {'dashboardcheck': 'Dashboard created!'};
    #cfnresponse.send(event, context, response.SUCCESS, responseData);
    # parsedUrl = url.parse(event.ResponseURL);

    # responseBody = {'Status': 'SUCCESS',
    #                 'Reason': '',
    #                 'PhysicalResourceId': '',
    #                 'StackId': event['StackId'],
    #                 'RequestId': event['RequestId'],
    #                 'LogicalResourceId': event['LogicalResourceId'],
    #                 'Data': {'Success': 'Test Passed.'}}
    # req = requests.put(event['ResponseURL'], data=json.dumps(responseBody))
    
    return 'Execution Complete'
