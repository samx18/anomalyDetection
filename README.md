# anomalyDetection

Using lambda to perform automated anamoly detection



## Deployment

Use the cloudformation template to create resources or create them manually 

`AnalysisLambdaFunction.py` - Main lambda function to detect & alarm 


## Testing

`ActivityGenLambda.py` - Lambda function to generate test activity


## Clean-up

`teardown.sh` - A bash script to teardown the stck if deployed with cloudformation. You can also delete the stack from the console after deleteing the S3 buckets manually 
