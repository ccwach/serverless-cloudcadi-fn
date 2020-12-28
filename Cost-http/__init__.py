import azure.functions as func

import logging
import requests
import json


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
    endpoint = os.environ["Endpoint"]
    key = os.environ["Key"]

    # Account Setting
    cloudAccountId = os.environ["CLOUD_ACCOUNT_ID"]

    if not endpoint:
        return func.HttpResponse("Missing ENDPOINT ENV", status_code=400)
    if not key:
        return func.HttpResponse("Missing Key ENV",status_code=400)
    if not cloudAccountId:
        return func.HttpResponse("Missing CLOUD_ACCOUNT_ID ENV",status_code=400)

    try:

        # Fetching Log Analytics Credential
        r = requests.post(endpoint + '/get/account/cloud')
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
    output = []
    count = 1

    while url != None:
        r = requests.get(url, headers=headers)
        output += (r.json()['data'])
        url = r.json()['nextLink']
        logging.info('*************')
        logging.info('count -'+ str(count))
        logging.info(url)
        logging.info(len(output))
        logging.info('*************')
        count += 1
    
    logging.info('Ending Process - Getting Cost Data (Azure Consumption API)')

    request_header = {'Content-Type': 'application/json', 'Accept':'application/json'}

    try:
        logging.info('Pushing Resource Data')
        requests.post(endpoint + "/temp/create/resource",json=output, headers=request_header)
    except Exception as err:
        func.HttpResponse(
             f"Failed to Push Resource Data {err}",
             status_code=500
        )

    try:
        logging.info('Pushing Cost Data')
        requests.post(endpoint + "/azure/create/cost",json=output, headers=request_header)
    except Exception as err:
        func.HttpResponse(
             f"Failed to Push Cost Data {err}",
             status_code=500
        )

    return func.HttpResponse(f"Successfully Sent")