import azure.functions as func

# Dependencies
import os
import requests
import urllib3
import json
from functools import reduce
import pandas as pd
import logging


"""
Env : 
    - ENDPOINT
    - KEY
    - CLOUD_ACCOUNT_ID

req : (http-trigger only)
    - date

"""


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Performance HTTP trigger function processed a request.')

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
             "Please pass a date on the query string or in the request body",
             status_code=400
        )


    # Date
    startDate = dateValue
    endDate = dateValue

    """ 
    Local Testing
    """
    # endpoint = 'http://localhost:5000'
    # key = '$2a$10$vvcw4DX9j/ZGS6mDXrCCb.6FQ4P/zZAHvI4SepxzBfdYMJ3zLGLva'
    # cloudAccountId = '73e4665b-5b09-4925-98de-712227a0d514'


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


    # Account Setting
    try:
        cloudAccountId = os.environ["CLOUD_ACCOUNT_ID"]
    except KeyError:
        logging.error('Missing CLOUD_ACCOUNT_ID ENV')
        return func.HttpResponse("Missing CLOUD_ACCOUNT_ID ENV",status_code=400)
    

    
    # Fetching Log Analytics Credential
    try:
        r = requests.post(endpoint + '/get/account/cloud', data={
            "cloudAccountId": cloudAccountId,
            "key": key
        })
        output = r.json()
        logging.info(f"output->{output}")

        workspaceId = output["workspaceId"]
        tenantId = output["tenantId"]
        clientId = output["clientId"]
        clientSecret = output["clientSecret"]

        loginURL = "https://login.microsoftonline.com/" + tenantId + "/oauth2/token"
        resource = "https://api.loganalytics.io"
        # url = "https://api.loganalytics.io/v1/workspaces/"+ workspaceId + '/query'

    except Exception as err:
        return func.HttpResponse(
             f"Failed while getting cloud credential {err}",
             status_code=500
        )



    def get_token(url, resource, Username, Password):
        """Get authorization token"""
        payload = {
            'grant_type': 'client_credentials',
            'client_id': Username,
            'client_secret': Password,
            'Content-Type': 'x-www-form-urlencoded',
            'resource': resource
        }
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        ApiReturn = requests.post(url, data=payload, verify= False)

        if ApiReturn.status_code == 200:
            ApiToken = json.loads(ApiReturn.content)['access_token']
            logging.info(f'Authenication Success:')

            return { "Authorization": str("Bearer "+ ApiToken), 'Content-Type': 'application/json'}
        elif ApiReturn.status_code == 401:
            err = json.loads(ApiReturn.content)
            logging.error(f"workspaceId - Failed. Due to {err['error']}. Error Description  {err['error_description']}")
            
            return func.HttpResponse(f"workspaceId - Failed. Due to {err['error']}. Error Description  {err['error_description']}",
             status_code=500 )
    
    token = get_token(loginURL, resource, clientId, clientSecret)
        
    def getLogAnalyticsData(query):
        Headers = token
        params = {"query": query}
        rowData = []
        for i in workspaceId:
            url = "https://api.loganalytics.io/v1/workspaces/"+ i + '/query'
            logging.info(f"url->{url}")
            result = requests.get(url, params=params, headers=Headers, verify=False)
            Table = result.json()['tables'][0]
            columnData =[ col['name'] for col in Table['columns'] ]
            rowData += result.json()['tables'][0]['rows']
        return pd.DataFrame(rowData, columns= columnData)

    
    # Application Container CPU in % (docker) 
    def getCPU():
        CPU_Query = 'Perf| where ( ObjectName == "Container" ) | where ( CounterName == "% Processor Time" )| where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +'))| summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'
        CPU_Query_Data = getLogAnalyticsData(CPU_Query)

        CPU_Query_Data.rename(columns={'TimeGenerated': "date",
                                    'Computer': 'instance_name',
                                    'InstanceName': 'container_name',
                                    "MV": "cpu_percentage_max",
                                    "AV": "cpu_percentage_avg",
                                    "P90": "cpu_percentage_p90",
                                    "P80": "cpu_percentage_p80",
                                    }, inplace=True)

        CPU_Query_Data.drop(['CounterName'], axis=1, inplace=True)
        return CPU_Query_Data

    # Application Container Memory in MB (docker) 
    def getMemory():
        Memory_Query = 'Perf  | where ( ObjectName == "Container" ) | where ( CounterName == "Memory Usage MB" )  | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +')) | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'

        Memory_Query_Data = getLogAnalyticsData(Memory_Query)

        Memory_Query_Data.rename(columns={'TimeGenerated': "date",
                                        'Computer': 'instance_name',
                                        'InstanceName': 'container_name',
                                        "MV": "memory_mb_max",
                                        "AV": "memory_mb_avg",
                                        "P90": "memory_mb_p90",
                                        "P80": "memory_mb_p80",
                                        }, inplace=True)

        Memory_Query_Data.drop(['CounterName'], axis=1, inplace=True)
        return Memory_Query_Data

    # Application Container Disk Read in MB (docker)
    def getDiskRead():
        Disk_Read_Query = 'Perf  | where ( ObjectName == "Container" ) | where ( CounterName == "Disk Reads MB" )  | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +')) | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'
        Disk_Read_Query_Data = getLogAnalyticsData(Disk_Read_Query)

        Disk_Read_Query_Data.rename(columns={'TimeGenerated': "date",
                                            'Computer': 'instance_name',
                                            'InstanceName': 'container_name',
                                            "MV": "disk_read_mb_max",
                                            "AV": "disk_read_mb_avg",
                                            "P90": "disk_read_mb_p90",
                                            "P80": "disk_read_mb_p80",
                                            }, inplace=True)

        Disk_Read_Query_Data.drop(['CounterName'], axis=1, inplace=True)
        return Disk_Read_Query_Data
 
    # Application Container Disk Wirte in MB (docker)
    def getDiskWirte():
        Disk_Write_Query = 'Perf  | where ( ObjectName == "Container" ) | where ( CounterName == "Disk Writes MB" )  | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +')) | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'
        Disk_Write_Query_Data = getLogAnalyticsData(Disk_Write_Query)

        Disk_Write_Query_Data.rename(columns={'TimeGenerated': "date",
                                        'Computer': 'instance_name',
                                        'InstanceName': 'container_name',
                                            "MV": "disk_write_mb_max",
                                            "AV": "disk_write_mb_avg",
                                            "P90": "disk_write_mb_p90",
                                            "P80": "disk_write_mb_p80",
                                            }, inplace=True)

        Disk_Write_Query_Data.drop(['CounterName'], axis=1, inplace=True)
        return Disk_Write_Query_Data

    # Application Container Network Receive in Bytes (docker)
    def getNetworkReceived():
        NetworkReceiveBytes_Query = 'Perf  | where ( ObjectName == "Container" ) | where ( CounterName == "Network Receive Bytes" )  | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +')) | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'
        NetworkReceiveBytes_Query_Data = getLogAnalyticsData(NetworkReceiveBytes_Query)

        NetworkReceiveBytes_Query_Data.rename(columns={'TimeGenerated': "date",
                                        'Computer': 'instance_name',
                                        'InstanceName': 'container_name',
                                            "MV": "network_received_bytes_max",
                                            "AV": "network_received_bytes_avg",
                                            "P90": "network_received_bytes_p90",
                                            "P80": "network_received_bytes_p80",
                                            }, inplace=True)

        NetworkReceiveBytes_Query_Data.drop(['CounterName'], axis=1, inplace=True)
        return NetworkReceiveBytes_Query_Data

    # Application Container Network Send in Bytes (docker)
    def getNetworkSent():
        NetworkSentBytes_Query = 'Perf  | where ( ObjectName == "Container" ) | where ( CounterName == "Network Send Bytes" )  | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +')) | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'

        NetworkSentBytes_Query_Data = getLogAnalyticsData(NetworkSentBytes_Query)

        NetworkSentBytes_Query_Data.rename(columns={'TimeGenerated': "date",
                                        'Computer': 'instance_name',
                                        'InstanceName': 'container_name',
                                            "MV": "network_sent_bytes_max",
                                            "AV": "network_sent_bytes_avg",
                                            "P90": "network_sent_bytes_p90",
                                            "P80": "network_sent_bytes_p80",
                                            }, inplace=True)
        NetworkSentBytes_Query_Data.drop(['CounterName'], axis=1, inplace=True)
        return NetworkSentBytes_Query_Data

    
    CPU = getCPU()
    Memory = getMemory()
    Disk_Read = getDiskRead()
    Disk_Wirte = getDiskWirte()
    Network_Received = getNetworkReceived()
    Network_Sent = getNetworkSent()



    # Merging all Performance data
    dfs = [CPU, Memory, Disk_Read, Disk_Wirte, Network_Received, Network_Sent]

    df_final = reduce(lambda left,right: pd.merge(left,right,on=['instance_name', 'container_name','date']), dfs)
    df_final['instance_name'] = df_final['instance_name'].str.upper()
    df_final['date'] = df_final['date'].str[:10]
    d = df_final.to_json(orient='records')
    josnData = json.loads(d)

    # Clean up
    del CPU, Memory, Disk_Read, Disk_Wirte, Network_Received, Network_Sent
    
    # Dividing List by 1000 record per chuck
    def divide_chunks(l, n):       
        # looping till length l 
        for i in range(0, len(l), n):  
            yield l[i:i + n]
    
    jdata = list(divide_chunks(josnData, 1000)) 


    for jd in jdata:

        payload={
        'cloud_account_id': cloudAccountId,
        'data': jd
        }

        headers = {'Content-Type': 'application/json', 'Accept':'application/json'}

        r = requests.post(endpoint +"/azure/application-insight/container/performance/create",json=payload, headers=headers)

    # clean up
    del josnData, payload 

    return func.HttpResponse(f" This HTTP Azure Application Container Performance triggered function executed successfully.")





