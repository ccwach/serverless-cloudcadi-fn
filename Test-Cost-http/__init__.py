
import azure.functions as func
import os
import requests
import urllib3
import json
from functools import reduce
import pandas as pd
import logging


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Cost Test Function Started')

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

    try:
        ENROLLMENT = os.environ['ENROLLMENT']
    except KeyError:
        logging.error('Missing ENROLLMENT ENV')
        return func.HttpResponse("Missing ENROLLMENT ENV", status_code=400)
    try:
        KEY = os.environ['TOKEN']
    except KeyError:
        logging.error('Missing TOKEN ENV')
        return func.HttpResponse("Missing TOKEN ENV", status_code=400)

    # Subscription list
    try:
        subscriptionList = os.environ["SUBSCRIPTION_LIST"].split(",")
    except KeyError:
        return logging.error('Missing Subscription List ENV')
    
    logging.info('Starting Process - Getting Cost Data (Azure Consumption API)')

    url = 'https://consumption.azure.com/v3/enrollments/'+ ENROLLMENT +'/usagedetailsbycustomdate?startTime='+ STARTDATE +'&endTime='+ ENDDATE
    headers = {'Accept':'application/json', 'Authorization': 'bearer '+ KEY}
    output = []
    count = 1

    while url != None:
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
    
    logging.info('Ending Process - Getting Cost Data (Azure Consumption API)')
    
    # Filtering Subcription
    costData = pd.DataFrame(output)
    costData = costData[costData['subscriptionName'].isin(subscriptionList)]

    logging.info(f"Sample output :- {output[0]}")

    return func.HttpResponse(f"Cost Test Function Successfully")
