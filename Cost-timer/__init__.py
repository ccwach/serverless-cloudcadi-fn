import azure.functions as func

from datetime import date, timedelta
import os
import logging
import requests
import json
import pandas as pd

def main(mytimer: func.TimerRequest) -> None:
    # Start
    dateValue = str(date.today()- timedelta(days= 2))

    STARTDATE = dateValue
    ENDDATE = dateValue


    """ 
    Local Testing
    """
    # endpoint = 'http://localhost:5000'
    # key = ''
    # cloudAccountId = '8f79e655-64ef-4983-9896-4d6437e4f0b8'

    # BackEnd Access Credential 
    try:
        endpoint = os.environ["ENDPOINT"]
    except KeyError:
        return logging.error('Missing ENDPOINT ENV')
        

    try:
        key = os.environ["KEY"]
    except KeyError:
        return logging.error('Missing KEY ENV')
        
    # Subscription list
    try:
        subscriptionList = os.environ["SUBSCRIPTION_LIST"].split(",")
    except KeyError:
        return logging.error('Missing Subscription List ENV')

    # Account Setting
    try:
        cloudAccountId = os.environ["CLOUD_ACCOUNT_ID"]
    except KeyError:
        return logging.error('Missing CLOUD_ACCOUNT_ID ENV')
    
    
    # Fetching Log Analytics Credential
    try:
        r = requests.post(endpoint + '/get/account/cloud', data={
            "cloudAccountId": cloudAccountId,
            "key": key
        })
        output = r.json()

        ENROLLMENT = output['enrollment']
        KEY = output['key']

    except Exception as err:
        return logging.error(
             f"Failed while getting cloud credential {err}"
        )

    logging.info('Starting Process - Getting Cost Data (Azure Consumption API)')

    url = 'https://consumption.azure.com/v3/enrollments/'+ ENROLLMENT +'/usagedetailsbycustomdate?startTime='+ STARTDATE +'&endTime='+ ENDDATE
    headers = {'Accept':'application/json', 'Authorization': 'bearer '+ KEY}
    output = []
    count = 1

    while url != None:
        r = requests.get(url, headers=headers)
        if r.status_code == 401:
            return logging.error(f"Authenication Failed:- {r.json()['error']}")
                
        output += (r.json()['data'])
        url = r.json()['nextLink']
        logging.info('*************')
        logging.info('count -'+ str(count))
        logging.info(url)
        logging.info(len(output))
        logging.info('*************')
        count += 1
    
    logging.info('Ending Process - Getting Cost Data (Azure Consumption API)')

    # Filtering Subcription
    costData = pd.DataFrame(output)
    costData = costData[costData['subscriptionName'].isin(subscriptionList)]

    request_header = {'Content-Type': 'application/json', 'Accept':'application/json'}
    
    payload = {
        'cloud_account_id': cloudAccountId,
        'data': json.loads(costData.to_json(orient='records'))
    }

    try:
        logging.info('Pushing Resource Data')
        requests.post(endpoint + "/temp/create/resource",json=payload, headers=request_header)
    except Exception as err:
        logging.error(
             f"Failed to Push Resource Data {err}"
        )

    try:
        logging.info('Pushing Cost Data')
        requests.post(endpoint + "/azure/create/cost",json=payload, headers=request_header)
    except Exception as err:
        logging.error(
             f"Failed to Push Cost Data {err}"
        )

    return logging.info(f"Successfully Sent")


