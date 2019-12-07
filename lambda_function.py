 # Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 # SPDX-License-Identifier: MIT-0
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy of this
 # software and associated documentation files (the "Software"), to deal in the Software
 # without restriction, including without limitation the rights to use, copy, modify,
 # merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 # permit persons to whom the Software is furnished to do so.
 #
 # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 # INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 # PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 # OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 # SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import json
import boto3
import datetime

def lambda_handler(event, context):
    # parse needed information from CloudWatch Event
    noncompliantInstance = str(event['detail']['resource-id'])
    cweEventType = str(event['detail-type'])
    ssmManagedResourceArn = str(event['resources'][0])
    accountId = str(event['account'])
    awsRegion = str(event['region'])
    
    # drop any SSM Compliance Items are are Compliant
    complianceDetail = str(event['detail']['compliance-status'])
    if complianceDetail != 'non_compliant':
        print("Ignoring Compliant Resource!")
        return 1
    else:
        print("Found non-compliant resource, proceeding")
    
    # at this point we identified a non-compliant instance
    # import boto3 clients & resources for SSM, EC2 and Security Hub
    ssm = boto3.client('ssm')
    ec2client = boto3.client('ec2')
    ec2 = boto3.resource('ec2')
    securityhub = boto3.client('securityhub')
    
    # use Ec2 Resource to pull out ASFF Ec2InstnaceInfo for mapping
    try:
        ec2InstanceIntel = ec2.Instance(noncompliantInstance)
        ec2Type = ec2InstanceIntel.instance_type
        ec2ImageId = ec2InstanceIntel.image_id
        ec2PubIPv4 = ec2InstanceIntel.public_ip_address
        ec2PrivIPv4 = ec2InstanceIntel.private_ip_address
        ec2KeyName = ec2InstanceIntel.key_name
        ec2InstanceProfile = ec2InstanceIntel.iam_instance_profile
        ec2SubnetInfo = ec2VpcInfo = ec2InstanceIntel.subnet_id
        ec2VpcInfo = ec2InstanceIntel.vpc_id
        ec2SecurityGroup = ec2InstanceIntel.security_groups
        securitygroupName = str(ec2SecurityGroup[0]['GroupName'])
        securitygroupId = str(ec2SecurityGroup[0]['GroupId'])
        print("EC2 data enrichment complete")
    except Exception as e:
        print(e)
        raise

    try:
        findNACL = ec2client.describe_network_acls(
        Filters=[
            {
                'Name' :'association.subnet-id',
                'Values': [ ec2SubnetInfo ]
            }
        ],
        DryRun=False
        )
        ec2NaclInfo = str(findNACL['NetworkAcls'][0]['Associations'][0]['NetworkAclId'])
        print(findNACL)
        print(noncompliantInstance + " " + "Network ACL identified")
    except Exception as e:
        print(e)
        raise

    # call SSM DescribeInstanceInformation API, pull out SSM Agent telemetry to map to ASFF Resource.Other field
    try:
        describeInstanceInformation = ssm.describe_instance_information(
        InstanceInformationFilterList=[
            {
                'key': 'InstanceIds',
                'valueSet': [ noncompliantInstance ]
            }
        ],
        MaxResults=20
        )
        ssmAgentVersion = str(describeInstanceInformation['InstanceInformationList'][0]['AgentVersion'])
        ssmPlatformType = str(describeInstanceInformation['InstanceInformationList'][0]['PlatformType'])
        ssmPlatformName = str(describeInstanceInformation['InstanceInformationList'][0]['PlatformName'])
        ssmPlatformVersion = str(describeInstanceInformation['InstanceInformationList'][0]['PlatformVersion'])
        print(describeInstanceInformation)
        print("SSM data enrichment complete")
    except Exception as e:
        print(e)

    # call SSM ListComplianceItems API, filter on non-compliant InSpec scans
    try:
        response = ssm.list_compliance_items(
        Filters=[
            {
                'Key': 'ComplianceType',
                'Values': [ 'Custom:InSpec' ],
                'Type': 'EQUAL'
            },
            {
                'Key': 'Status',
                'Values': [ 'NON_COMPLIANT' ],
                'Type': 'EQUAL'
            }
        ],
        ResourceTypes=[ 'ManagedInstance' ],
        ResourceIds=[ noncompliantInstance ],
        MaxResults=50
        )
    except Exception as e:
        print(e)
        raise

    # pull out & loop through needed information from SSM ComplianceItems API to map to ASFF

    for item in response['ComplianceItems']:
        inspecControlId = str(item['Id'])
        inspecControlTitle = str(item['Title'])
        ssmComplianceSeverity = str(item['Severity'])
        ssmExecutionId = str(item['ExecutionSummary']['ExecutionId'])
        ssmExecutionType = str(item['ExecutionSummary']['ExecutionType'])

        # map ASFF Severity based on SSM Compliance Severty
        # SSM = 'Severity': 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFORMATIONAL'|'UNSPECIFIED'
        # SecHub = Allowed values are the following: PASSED, WARNING, FAILED, NOT_AVAILABLE
        if ssmComplianceSeverity == 'UNSPECIFIED':
            ssmASFFComplianceStatus = 'NOT_AVAILABLE'
            ssmASFFProductSeverity = int(1)
            ssmASFFProductNormalized = int(1)
        elif ssmComplianceSeverity == 'INFORMATIONAL':
            ssmASFFComplianceStatus = 'WARNING'
            ssmASFFProductSeverity = int(1)
            ssmASFFProductNormalized = int(1)
        elif ssmComplianceSeverity == 'LOW':
            ssmASFFComplianceStatus = 'FAILED'
            ssmASFFProductSeverity = int(1)
            ssmASFFProductNormalized = int(11)
        elif ssmComplianceSeverity == 'MEDIUM':
            ssmASFFComplianceStatus = 'FAILED'
            ssmASFFProductSeverity = int(4)
            ssmASFFProductNormalized = int(41)
        elif ssmComplianceSeverity == 'HIGH':
            ssmASFFComplianceStatus = 'FAILED'
            ssmASFFProductSeverity = int(7)
            ssmASFFProductNormalized = int(71)
        elif ssmComplianceSeverity == 'CRITICAL':
            ssmASFFComplianceStatus = 'FAILED'
            ssmASFFProductSeverity = int(9)
            ssmASFFProductNormalized = int(91)
        else:
            print("No Compliance Info Found!")
        
        print("Security Hub Severity identified as:" + " " + ssmComplianceSeverity)
        
        # map SSM, EC2 and CloudWatch Information into ASFF and send to Security Hub
        # ISO Time
        iso8061Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        # ASFF BIF Id
        try:
            response = securityhub.batch_import_findings(
            Findings=[
                {
                    'SchemaVersion': '2018-10-08',
                    'Id': noncompliantInstance + '/' + inspecControlId,
                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + accountId + ':product/' + accountId + '/default',
                    'GeneratorId': ssmExecutionId,
                    'AwsAccountId': accountId,
                    'Types': [ 'Software and Configuration Checks' ],
                    'FirstObservedAt': iso8061Time,
                    'UpdatedAt': iso8061Time,
                    'CreatedAt': iso8061Time,
                    'Severity': {
                        'Product': ssmASFFProductSeverity,
                        'Normalized': ssmASFFProductNormalized
                    },
                    'Confidence': 99,
                    'Title': 'EC2 Instance' + ' ' + noncompliantInstance + ' has failed InSpec Check ' + inspecControlId,
                    'Description': 'EC2 Instance ' + noncompliantInstance + ' has failed InSpec Check ' + inspecControlId + ' Check Title: ' + inspecControlTitle,
                    'ProductFields': {
                        'Provider Name': 'AWS Systems Manager Compliance'
                    },
                    'UserDefinedFields': {
                        'CloudWatch Detail Type': cweEventType
                    },
                    'Resources': [
                        {
                            'Type': 'AwsEc2Instance',
                            'Id': 'arn:aws:ec2:' + awsRegion + ':' + accountId + ':' + 'instance/' + noncompliantInstance,
                            'Partition': 'aws',
                            'Region': awsRegion,
                            'Details': {
                                'AwsEc2Instance': {
                                    'Type': ec2Type,
                                    'ImageId': ec2ImageId,
                                    'IpV4Addresses': [ ec2PrivIPv4, ec2PubIPv4 ],
                                    'KeyName': ec2KeyName,
                                    'IamInstanceProfileArn': ec2InstanceProfile['Arn'],
                                    'VpcId': ec2VpcInfo,
                                    'SubnetId': ec2SubnetInfo
                                },
                                "Other": { 
                                    "Instance ID" : noncompliantInstance,
                                    "Network ACL ID" : ec2NaclInfo,
                                    "Security Group Name" : securitygroupName,
                                    "Security Group Id" : securitygroupId,
                                    "SSM Agent Version" : ssmAgentVersion,
                                    "SSM Platform Type" : ssmPlatformType,
                                    "SSM Platform Name" : ssmPlatformName,
                                    "SSM Platform Version" : ssmPlatformVersion,
                                    'InSpec Profile Title': inspecControlId,
                                    'SSM Execution Type': ssmExecutionType,
                                    'SSM Managed Instance ARN': ssmManagedResourceArn
                                }
                            }
                        },
                    ],
                    'Compliance': {'Status': ssmASFFComplianceStatus},
                    'VerificationState': 'TRUE_POSITIVE',
                    'WorkflowState': 'NEW',
                    'RecordState': 'ACTIVE'
                }
            ]
            )
            print(response)
        except Exception as e:
            print(e)
            raise