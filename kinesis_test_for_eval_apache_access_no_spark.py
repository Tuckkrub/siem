import json 
import numpy as np
import time
import pandas as pd
import re
import math
import joblib



# Set up the Kinesis stream
kinesisStreamName = "siem-log-stream"
kinesisAppName = "lastest_test"
kinesisEndpointURL = "https://kinesis.us-east-1.amazonaws.com"
kinesisRegionName = "us-east-1"
###############################################S3 indexer#####################
# indexer_dnsmasq = StringIndexerModel.read().load("s3a://siemtest22/model/indexer.model")
# indexer_error = StringIndexerModel.read().load("s3a://siemtest22/model/indexer.model")
#######################################################################
###################################################local indexer###############
# indexer_dnsmasq = './Indexer_no_spark/key_value_list.txt'
model_path='./model/ML_trained_model2/Access_rf_model.pkl'
# indexer_error = StringIndexerModel.read().load("s3://siemtest22/siem_spark_model/siem dev2/model/indexer_apacheerror")
################################################################################
loaded_rf_model_access=joblib.load(model_path)
################regex for building key-value ######################################################################
access_regex = r"([a-z]+\[?[A-Z]*\]?)\s(\S+)\s([fromtois]+)\s(\S+)"
error_regex_final_maybe=r"([^:']+:?)(('[^']+')?(\snot found or unable to stat))?(\s*([^\/:,'\(]+:?[^:\/,'\(]+:?)\s*(.*?(?=, referer|$)))?((, referer:)(.*))?"
###########################################################################################################




###########################################for apache access#########################################################
# Define Function
def check_agent(value):    
    if 'nmap' in value.lower() or 'wpscan' in value.lower() or 'python-requests' in value.lower():
        return 1
    elif 'mozilla/4.0 ' in value.lower():
        return 2
    else:
        return 0
    
def code_ext(value):
    return int(value[0])

def hidden_dir(value):
    if isinstance(value, str) and (value.startswith('/.') or value.startswith('/~') or value.startswith('/_')):
        return 1
    else:
        return 0

def count_slash(s):
    if isinstance(s, str):  # Check if 's' is a string
        return s.count('/')
    else:
        return 0

def has_special_char_in_path(value):
    if pd.notna(value) and isinstance(value, str) and any(char in value for char in ['%', '&', '=', '?']):
        return 1
    else:
        return 0

def encode_method(value, values_list = ['-', 'OPTIONS', 'HEAD', 'GET','POST']):
    try:
        return values_list.index(value)
    except ValueError:
        return -1  # Return -1 if value is not found in the list   


def process_access_for_pred(df):
    df['check_agent'] = df['agent'].apply(check_agent)    
    df['code'] = df['code'].astype(str)
    df['code_ext'] = df['code'].apply(code_ext)
    df['hidden_dir'] = df['path'].apply(hidden_dir)
    df['count_slash'] = df['path'].apply(count_slash)
    
    df['time'] = df['time'].astype(str)

    # Truncate timestamp to second
    df['timestamp_second'] = df['time'].str.slice(0, 19)

    # Assign unique IDs to each row
    df['id'] = range(len(df))

    # Group by host and truncated timestamp, count entries
    df_grouped = df.groupby(["host", "timestamp_second"]).size().reset_index(name="entries_in_second")

    # Join grouped DataFrame with original data DataFrame
    df = pd.merge(df, df_grouped, on=["host", "timestamp_second"], how="left")

    # Sort the resulting DataFrame based on IDs
    df.sort_values(by='id', inplace=True)


    df['has_special_char_in_path'] = df['path'].apply(has_special_char_in_path)
    df['size_int'] = pd.to_numeric(df['size'], errors='coerce')
    df['encode_method'] = df['method'].apply(encode_method)
    
    return df

    
def process_access(df):  # Replace 'your_regex_pattern_here' with your actual regex pattern
    return df
######################################################for apache access #########################################

##########################################for apache error####################################################

    

###############################################################################################################
def process_rdd(path):
    df=pd.read_json(path,lines=True)
    print("enter check")
    start_time_process = time.time()
    print("***** phase 1 access log seperation ******")
    df=process_access(df)
            
    start_time_dns = time.time()
    # dataframes['dnsmasq'].show()
    unique_owners=df['owner'].unique()
            # unique_owners.show()
    print("Phase 1 - Completed")
            
    end_time_dns = time.time()

    elapsed_time1 = end_time_dns - start_time_dns
    print("log seperation time <access_phase_1>:", elapsed_time1, "seconds\n")

        #############LET's seperate by log owner#################################
            
    print("***** phase 2 access owner seperation & furthur pre-processing ******")
    for row in unique_owners:         
            start_time_dns = time.time()

                    # since only 1 column is collected , so it's always at row[0]
            owner = row
            df_temp = df.loc[df['owner'] == owner]
                    # owner = df_temp.select("owner").first()[0]
                    # df_temp.show()
            print("Phase 2 - Completed")
            df_pyspark = df_temp.copy()
               

                 # df_pyspark.show()
            end_time_dns = time.time()

            elapsed_time2 = end_time_dns - start_time_dns
            print(f"Pre-processed time <access_phase_2_{owner}>:", elapsed_time2, "seconds\n")

                    # send to anomaly module
            print("***** phase 3 access  anomaly detection ******")
            
            start_time_dns = time.time()
            df_pyspark = process_access_for_pred(df_pyspark) 
            list_of_columns = [
                'check_agent',
                'code_ext',
                'hidden_dir',
                'count_slash',
                'entries_in_second',
                'size_int',
                'has_special_char_in_path',
                'encode_method'
            ]
            df_pyspark=df_pyspark[list_of_columns]
            df_pyspark['prediction']=loaded_rf_model_access.predict(df_pyspark)
            count_ones = df_pyspark['prediction'].eq(1).sum()
            count_zeros = df_pyspark['prediction'].eq(0).sum()

            print(f"Count of 1s: {count_ones}")
            print(f"Count of 0s: {count_zeros}")
            print("Phase 3 - Prediction Ended")
            end_time_dns = time.time()
            elapsed_time4 = end_time_dns - start_time_dns
            print(f"Anomaly detection time <access_phase_4_{owner}>:", elapsed_time4, "seconds\n")
                    ########################
            print("*********************************** END ***********************************\n")
            print("Pre-processed time <access_phase_1>:", elapsed_time1, "seconds\n")
            print(f"Pre-processed time <access_phase_2_{owner}>:", elapsed_time2, "seconds\n")
            print(f"Anomaly detection time <access_phase_3_{owner}>:", elapsed_time4, "seconds\n")
    end_time_process = time.time()
    process_time=end_time_process-start_time_process
    print(f"overall elapse time: {process_time}", "seconds\n")
                    
           
            # dataframes['dnsmasq'].write.mode('overwrite').parquet("C:\\Users\\A570ZD\\Desktop\\kinesis_stream\\temp\\dnsmasq") 
        
def read_txt_to_list(file_path):
    lines_list = []
    with open(file_path, 'r') as file:
        for line in file:
            lines_list.append(line.strip())  # strip() removes any leading/trailing whitespaces including '\n'
    return lines_list

print("read all test set , prepare for testing")
list_spark=[
    "s3://siemtest22/siem_spark_model/eval_data2/apache2_access_normalized_client13_500.json/part-00000-8dc6b766-b5b3-4b2a-8db6-0f275031a89a-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/apache2_access_normalized_client13_1000.json/part-00000-eddd6f27-48da-4033-b299-e2ad4b0d4b92-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/apache2_access_normalized_client13_2000.json/part-00000-8c37609e-8248-4116-9d67-57f2f3bab805-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/apache2_access_normalized_client13_4000.json/part-00000-ddc0bac8-0e29-42c3-8825-c5b00e7531f4-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/apache2_access_normalized_client13_8000.json/part-00000-44f67403-f500-4621-8829-84e20ae4b24f-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/apache2_access_normalized_client13_16000.json/part-00000-34b124d8-eecb-4236-a36e-d40e86f03526-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/apache2_access_normalized_client13_32000.json/part-00000-04a183b1-c861-4900-892e-6f1e84e40436-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/apache2_access_normalized_client13_64000.json/part-00000-ed0898f4-cd28-4472-b198-3d0c91a2f87a-c000.json",    
    "s3://siemtest22/siem_spark_model/eval_data2/apache2_access_normalized_client13_128000.json/part-00000-a973f44e-bf1f-4382-aff9-7ac187a70154-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/apache2_access_normalized_client13_256000.json/part-00000-b9cbfd72-35d8-4b16-97ee-8c792620f469-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/apache2_access_normalized_client13_512000.json/part-00000-512000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/apache2_access_normalized_client13_1024000.json/part-00000-1024000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/apache2_access_normalized_client13_2048000.json/part-00000-2048000.json"
    ]
for i in list_spark:
    process_rdd(i)

#vv
