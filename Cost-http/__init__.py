import azure.functions as func

import os
import logging
import requests
import json
import pandas as pd

def main(req: func.HttpRequest) -> func.HttpResponse:
    # Start

    dateValue = req.params.get('date')
    if not dateValue:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            dateValue = req_body.get('date')

    if dateValue:
        logging.info(f"Getting LogAnalytics Data for {dateValue}")
    else:
        return func.HttpResponse(
            "Please pass a Date on the query string or in the request body",
            status_code=400
        )


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
        logging.error('Missing ENDPOINT ENV')
        return func.HttpResponse("Missing ENDPOINT ENV", status_code=400)

    try:
        key = os.environ["KEY"]
    except KeyError:
        logging.error('Missing KEY ENV')
        return func.HttpResponse("Missing KEY ENV",status_code=400)

    # Subscription list
    try:
        subscriptionList = os.environ["SUBSCRIPTION_LIST"].split(",")
    except KeyError:
        return logging.error('Missing Subscription List ENV')


    # Account Setting
    try:
        cloudAccountId = os.environ["CLOUD_ACCOUNT_ID"]
    except KeyError:
        logging.error('Missing CLOUD_ACCOUNT_ID ENV')
        return func.HttpResponse("Missing CLOUD_ACCOUNT_ID ENV",status_code=400)
    

    # Fetching Log Analytics Credential
    try:
        r = requests.post(endpoint + '/get/account/cloud',data={
            "cloudAccountId": cloudAccountId,
            "key": key
        })
        output = r.json()

        ENROLLMENT = output['enrollment']
        KEY = output['key']

    except Exception as err:
        return func.HttpResponse(
             f"Failed while getting cloud credential {err}",
             status_code=500
        )

    logging.info('Starting Process - Getting Cost Data (Azure Consumption API)')

    url = 'https://consumption.azure.com/v3/enrollments/'+ ENROLLMENT +'/usagedetailsbycustomdate?startTime='+ STARTDATE +'&endTime='+ ENDDATE
    headers = {'Accept':'application/json', 'Authorization': 'bearer '+ KEY}
    output = []
    count = 1

    while url != None:
        try:
            r = requests.get(url, headers=headers)
            if r.status_code == 401:
                logging.error(f"Authenication Failed:- {r.json()['error']}")
                return func.HttpResponse(f"Authenication Failed:- {r.json()['error']}",status_code=401)
                    
            output += (r.json()['data'])
            url = r.json()['nextLink']
            logging.info('*************')
            logging.info('count -'+ str(count))
            logging.info(url)
            logging.info(len(output))
            logging.info('*************')
            count += 1
        except Exception as err:
            return func.HttpResponse(
                f"Failed while getting Cost Data from Azure Consumption API {err}",
                status_code=500
            )
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
        func.HttpResponse(
             f"Failed to Push Resource Data {err}",
             status_code=500
        )

    try:
        logging.info('Pushing Cost Data')
        requests.post(endpoint + "/azure/create/cost",json=payload, headers=request_header)
    except Exception as err:
        func.HttpResponse(
             f"Failed to Push Cost Data {err}",
             status_code=500
        )

    # Cleanup 
    del output, costData, payload

    return func.HttpResponse(f"Successfully Sent")