## Continuous compliance monitoring with Chef InSpec and AWS Security Hub

This is sample code for the accompanying AWS Security Blog post Continuous compliance monitoring with Chef InSpec and AWS Security Hub. Python 3.7 code for the Lambda function and a YAML CloudFormation script are provided.

### Solutions Architecture
![Architecture](https://github.com/aws-samples/securityhub-ssm-inspec-integration/blob/master/Architecture.jpg)
1.	Invoke AWS-RunInSpecChecks document on-demand by using Run Command against your target instances (State Manager is another option for scheduling InSpec scans, but is not covered in this blog post).
2.	Systems Manager downloads the InSpec Ruby files from Amazon Simple Storage Service (Amazon S3), installs InSpec on your server, runs the scan, and removes InSpec when complete.
3.	AWS Systems Manager pushes scan results to the Compliance API and presents the information in the Systems Manager Compliance console, to include severity and compliance state.
4.	A CloudWatch Event is emitted for Compliance state changes.
5.	A CloudWatch Event Rule listens for these state changes and when detected, invokes a Lambda function. 
6.	Lambda calls the Compliance APIs for additional data about which InSpec check failed, and enriches the data with information from the Systems Manager API DescribeInstanceInformation action.
7.	Lambda calls the EC2 APIs to further enrich the data about the non-compliant instance.
8.	Lambda maps these details to the AWS Security Finding Format and sends them to Security Hub.

#### Lambda function modification

Due to character contraints (4096) for Lambda functions written in-line within CloudFormation, you will need to modify the function. Download `lambda_function.py` and either paste it in within the Lambda console or ZIP it and change it that way.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

