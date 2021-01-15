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

    
    def getCPU():
        CPU_Query = 'Perf | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +')) | where ( ObjectName == "Processor" ) | where ( CounterName == "% Processor Time" ) | where ( InstanceName == "_Total" ) | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'
        CPU_Data = getLogAnalyticsData(CPU_Query)
        
        # Formatting
        CPU_Data.rename(columns={ 'P90': 'CPU_P90', 'P80': 'CPU_P80','AV': 'CPU_AV', 'MV': 'CPU_MV', 'TimeGenerated': 'Date', 'Computer': 'COMPUTER'}, inplace= True)
        CPU_Data.drop(['InstanceName', 'CounterName'], axis=1 , inplace=True)

        logging.info('CPU Data Collected')
        
        return CPU_Data

    def getMemory():

    # Two different Counter name for windows and linux
    # Linux - "Used Memory MBytes" and "% Used Memory" ( Implm in getLinuxMachineMemory function)
    # Window - "% Committed Bytes In Use" and "Committed Bytes" ( Implm in getWindowsMachineMemory function)
    
    
        def getLinuxMachineMemory():
            
            # *** - Linux - ***
            Memory_Linux_Query = 'Perf | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +')) | where ( ObjectName == "Memory" ) | where ( CounterName == "Used Memory MBytes" or CounterName == "% Used Memory" )  | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'
            Memory_Linux_Data = getLogAnalyticsData(Memory_Linux_Query)

            # Formatting
            Memory_Linux_Percentage = Memory_Linux_Data[Memory_Linux_Data['CounterName'] == '% Used Memory']
            Memory_Linux_GB = Memory_Linux_Data[Memory_Linux_Data['CounterName'] == 'Used Memory MBytes']
            Memory_Linux = pd.merge(Memory_Linux_Percentage, Memory_Linux_GB, on='Computer')
            Memory_Linux.rename(columns={ 'TimeGenerated_x': "Date", 
                                "MV_x": "Memory_MV_Percentage", 
                                "AV_x": "Memory_AV_Percentage", 
                                "P90_x": "Memory_P90_Percentage", 
                                "P80_x": "Memory_P80_Percentage",
                                "MV_y": "Memory_MV_GB", 
                                "AV_y": "Memory_AV_GB", 
                                "P90_y": "Memory_P90_GB", 
                                "P80_y": "Memory_P80_GB",
                                'Computer': 'COMPUTER'
                                }, inplace=True)
            Memory_Linux.drop(['InstanceName_x', 'CounterName_x', 'TimeGenerated_y', 'CounterName_y', 'InstanceName_y'], axis=1, inplace=True)
            
            return Memory_Linux
        
        def getWindowsMachineMemory():
            
            # *** - Window - ***
            Memory_Window_Query = 'Perf | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +')) | where ( ObjectName == "Memory" ) | where ( CounterName == "% Committed Bytes In Use" or CounterName == "Committed Bytes" )  | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'
            Memory_Window_Data = getLogAnalyticsData(Memory_Window_Query)
            
            
            # Formatting
            Memory_Window_Percentage = Memory_Window_Data[Memory_Window_Data['CounterName'] == '% Committed Bytes In Use']
            Memory_Window_GB = Memory_Window_Data[Memory_Window_Data['CounterName'] == 'Committed Bytes']
            
            # Converting Bytes to GB
            Memory_Window_GB['MV'] = Memory_Window_GB['MV'] /1024 /1024
            Memory_Window_GB['AV'] = Memory_Window_GB['AV'] /1024 /1024
            Memory_Window_GB['P90'] = Memory_Window_GB['P90'] /1024 /1024
            Memory_Window_GB['P80'] = Memory_Window_GB['P80'] /1024 /1024
            
            Memory_Windows = pd.merge(Memory_Window_Percentage, Memory_Window_GB, on='Computer')
            Memory_Windows.rename(columns={ 'TimeGenerated_x': "Date", 
                            "MV_x": "Memory_MV_Percentage", 
                            "AV_x": "Memory_AV_Percentage", 
                            "P90_x": "Memory_P90_Percentage", 
                            "P80_x": "Memory_P80_Percentage",
                            "MV_y": "Memory_MV_GB", 
                            "AV_y": "Memory_AV_GB", 
                            "P90_y": "Memory_P90_GB", 
                            "P80_y": "Memory_P80_GB",
                            'Computer': 'COMPUTER'
                            }, inplace=True)
            Memory_Windows.drop(['InstanceName_x', 'CounterName_x', 'TimeGenerated_y', 'CounterName_y', 'InstanceName_y'], axis=1, inplace=True)
            
            return Memory_Windows
        
        # Merging both linux and windows output
        LMemory = getLinuxMachineMemory()
        WMemory = getWindowsMachineMemory()
        
        Memory = LMemory.append(WMemory)
        
        logging.info('Memory Data Collected')

        return  Memory

    def getDiskReadBySec():
        DRQuery = 'Perf | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +')) | where ( ObjectName == "LogicalDisk" or ObjectName == "Logical Disk" ) | where ( CounterName == "Disk Reads/sec" ) | where ( InstanceName == "_Total" ) | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'
        DRData = getLogAnalyticsData(DRQuery)
        
        # Formatting
        DRData.rename(columns={'TimeGenerated' : 'Date',  'MV': 'DR_MV', 'AV': 'DR_AV', 'P90': 'DR_P90', 'P80': 'DR_P80', 'Computer': 'COMPUTER'}, inplace=True)
        DRData.drop(['InstanceName', 'CounterName'], axis=1, inplace=True)
        
        logging.info('DRData Data Collected')

        return DRData

    
    def getDiskWriteBySec():
        DWQuery = 'Perf | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +')) | where ( ObjectName == "LogicalDisk" or ObjectName == "Logical Disk" ) | where ( CounterName == "Disk Writes/sec" ) | where ( InstanceName == "_Total" ) | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'
        DWData = getLogAnalyticsData(DWQuery)
        
        # Formatting
        DWData.rename(columns={'TimeGenerated' : 'Date',  'MV': 'DW_MV', 'AV': 'DW_AV', 'P90': 'DW_P90', 'P80': 'DW_P80', 'Computer': 'COMPUTER'}, inplace=True)
        DWData.drop(['InstanceName', 'CounterName'], axis=1, inplace=True)
        
        logging.info('DWData Data Collected')
        
        return DWData

    def getNetworkSent():
        NetworkSentQuery = 'Perf | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +')) | where ( ObjectName == "Network Adapter"  or  ObjectName == "Network" ) | where ( CounterName == "Bytes Sent/sec" or CounterName == "Total Bytes Transmitted") | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName'
        NetworkSentData = getLogAnalyticsData(NetworkSentQuery)
        
        #Formatting
        NetworkSentData.rename(columns={'TimeGenerated' : 'Date',  'MV': 'NetworkSent_MV', 'AV': 'NetworkSent_AV', 'P90': 'NetworkSent_P90', 'P80': 'NetworkSent_P80', 'Computer': 'COMPUTER'}, inplace=True)    
        NetworkSentData.drop(['CounterName'], axis=1, inplace=True)
        
        logging.info('NetworkSentData Data Collected')
        
        return NetworkSentData
    
    def getNetworkReceived():
        NetworkReceivedQuery = 'Perf | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +')) | where ( ObjectName == "Network" or ObjectName == "Network Adapter" ) | where ( CounterName == "Total Bytes Received" or CounterName == "Bytes Received/sec") | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName'
        NetworkReceivedData = getLogAnalyticsData(NetworkReceivedQuery)
        
        # Farmatting
        NetworkReceivedData.rename(columns={'TimeGenerated' : 'Date',  'MV': 'NetworkReceived_MV', 'AV': 'NetworkReceived_AV', 'P90': 'NetworkReceived_P90', 'P80': 'NetworkReceived_P80', 'Computer': 'COMPUTER'}, inplace=True)
        NetworkReceivedData.drop(['CounterName'], axis=1, inplace=True)
        
        logging.info('NetworkReceivedData Data Collected')

        return NetworkReceivedData

    
    def getDiskReadBytesBySec():
        StorageDiskReadQuery = 'Perf | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +'))| where (ObjectName == "LogicalDisk" or ObjectName == "Logical Disk"  )| where ( CounterName == "Disk Read Bytes/sec"  )| where ( InstanceName == "_Total") | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'
        StorageDiskReadData = getLogAnalyticsData(StorageDiskReadQuery)
        
        StorageDiskReadData.rename(columns={'TimeGenerated' : 'Date',  'MV': 'StorageDiskRead_MV', 'AV': 'StorageDiskRead_AV', 'P90': 'StorageDiskRead_P90', 'P80': 'StorageDiskRead_P80', 'Computer': 'COMPUTER'}, inplace=True)
        StorageDiskReadData.drop(['InstanceName','CounterName'], axis=1, inplace=True)
        
        logging.info('StorageDiskReadData Data Collected')

        return StorageDiskReadData

    def getDiskWriteBytesBySec():
        StorageDiskWriteQuery = 'Perf | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +'))| where (ObjectName == "LogicalDisk" or ObjectName == "Logical Disk"  )| where ( CounterName == "Disk Write Bytes/sec"  )| where ( InstanceName == "_Total") | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'
        StorageDiskWriteData = getLogAnalyticsData(StorageDiskWriteQuery)
        
        # Formatting
        StorageDiskWriteData.rename(columns={'TimeGenerated' : 'Date',  'MV': 'StorageDiskWrite_MV', 'AV': 'StorageDiskWrite_AV', 'P90': 'StorageDiskWrite_P90', 'P80': 'StorageDiskWrite_P80', 'Computer': 'COMPUTER'}, inplace=True)
        StorageDiskWriteData.drop(['InstanceName','CounterName'], axis=1, inplace=True)

        logging.info('StorageDiskWriteData Data Collected')
        
        return StorageDiskWriteData


    def getStorage():
    
    # Two different Counter name for windows and linux
    # Linux - "% Used Space" ( Implm in getLinuxMachineMemory function)
    # Window - "% Free Space" ( Implm in getWindowsMachineMemory function)
    
        def getLinuxMachineStorage():
            
            Storage_Linux_Query = 'Perf | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +'))| where (ObjectName == "LogicalDisk" or ObjectName == "Logical Disk"  )| where (CounterName == "% Used Space" )| where ( InstanceName == "_Total") | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'
            Storage_Linux_Data = getLogAnalyticsData(Storage_Linux_Query)
            
            Storage_Linux_Data.rename(columns={ 'TimeGenerated': "Date", 
                            "MV": "Storage_MV_Percentage", 
                            "AV": "Storage_AV_Percentage", 
                            "P90": "Storage_P90_Percentage", 
                            "P80": "Storage_P80_Percentage",
                            'Computer': 'COMPUTER'
                            }, inplace=True)
            Storage_Linux_Data.drop(['CounterName', 'InstanceName'], axis=1, inplace=True)
            
            return Storage_Linux_Data
        
        def getWindowsMachineStorage():

            Storage_Windows_Query = 'Perf | where TimeGenerated > startofday(datetime('+ str(startDate) +')) and TimeGenerated < endofday(datetime('+ str(endDate) +'))| where (ObjectName == "LogicalDisk" or ObjectName == "Logical Disk"  )| where (CounterName == "% Free Space" )| where ( InstanceName == "_Total") | summarize MV = max(CounterValue), AV = avg(CounterValue), P90 = percentile(CounterValue, 90), P80 = percentile(CounterValue, 80) by bin(TimeGenerated, 1d), Computer, CounterName, InstanceName'
            Storage_Windows_Data = getLogAnalyticsData(Storage_Windows_Query)

            # Converting "% Free Space" to "% Used Space" by (100 - "% Free Space")
            Storage_Windows_Data['MV'] = 100 -  Storage_Windows_Data['MV']
            Storage_Windows_Data['AV'] = 100 -  Storage_Windows_Data['AV']
            Storage_Windows_Data['P90'] = 100 -  Storage_Windows_Data['P90']
            Storage_Windows_Data['P80'] = 100 -  Storage_Windows_Data['P80']
            
            # Formatting 
            Storage_Windows_Data.rename(columns={ 'TimeGenerated': "Date", 
                            "MV": "Storage_MV_Percentage", 
                            "AV": "Storage_AV_Percentage", 
                            "P90": "Storage_P90_Percentage", 
                            "P80": "Storage_P80_Percentage",
                            'Computer': 'COMPUTER'
                            }, inplace=True)
            Storage_Windows_Data.drop(['CounterName', 'InstanceName'], axis=1, inplace=True)

            return Storage_Windows_Data
        
        LStorage = getLinuxMachineStorage()
        WStorage = getWindowsMachineStorage()
        
        Storage = LStorage.append(WStorage)
        
        logging.info('Storages Data Collected')

        return Storage

    
    CPU = getCPU()
    Memory = getMemory()
    Disk_Read = getDiskReadBySec()
    Disk_Write = getDiskWriteBySec()
    Storage_Disk_Read = getDiskReadBytesBySec()
    Storage_Disk_Write = getDiskWriteBytesBySec()
    Network_Received = getNetworkReceived()
    Network_Sent = getNetworkSent()
    Storage = getStorage()


    # Merging all Performance data
    dfs = [CPU, Memory, Disk_Read, Disk_Write, Storage_Disk_Read, Storage_Disk_Write, Network_Received, Network_Sent, Storage ]

    df_final = reduce(lambda left,right: pd.merge(left,right,on=['COMPUTER', 'Date']), dfs)
    df_final['COMPUTER'] = df_final['COMPUTER'].str.upper()
    d = df_final.to_json(orient='records')
    josnData = json.loads(d)

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

        r = requests.post(endpoint +"/temp/create/performance",json=payload, headers=headers)
    

    return func.HttpResponse(f" This HTTP Performance triggered function executed successfully.")





