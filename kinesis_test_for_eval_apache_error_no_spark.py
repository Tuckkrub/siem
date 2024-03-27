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
model_path='./model/ML_trained_model2/Error_rf_model.pkl'
# indexer_error = StringIndexerModel.read().load("s3://siemtest22/siem_spark_model/siem dev2/model/indexer_apacheerror")
################################################################################
loaded_rf_model_apache_error=joblib.load(model_path)
################regex for building key-value ######################################################################
dnsmasq_regex = r"([a-z]+\[?[A-Z]*\]?)\s(\S+)\s([fromtois]+)\s(\S+)"
error_regex_final_maybe=r"([^:']+:?)(('[^']+')?(\snot found or unable to stat))?(\s*([^\/:,'\(]+:?[^:\/,'\(]+:?)\s*(.*?(?=, referer|$)))?((, referer:)(.*))?"
###########################################################################################################




###########################################for apache error#########################################################

# Define Function
def key_isAH(value):
    if value is not None and value.startswith('AH'): 
        return 1
    else:
        return 0
    
# isInvalid
def value_isInvalid(value):
    return 1 if 'invalid' in value.lower() else 0

def value_isforbidden(value):
    return 1 if 'forbidden' in value.lower() else 0

# isFail
def value_isFail(value):
    return 1 if 'fail' in value.lower() else 0

# script && not found
def key_script_not_found(value):
    return 1 if ('script' in value.lower()) and ('not found' in value.lower()) else 0

# time interval (action per sec)

# isFatal
def key_isFatal(value):
    return 1 if 'fatal' in value.lower() else 0

# isscandir
def key_isscandir(value):
    return 1 if 'scandir' in value.lower() else 0

# level isError
def level_isError(value):
    characters = ['error', 'emerg', 'alert', 'crit']
    if value is not None and any(char in value.lower() for char in characters):
        return 1
    else:
        return 0




def process_apache_error_for_pred(df):
    df['key_isAH'] = df['message'].apply(key_isAH)
    df['value_isInvalid'] = df['message'].apply(value_isInvalid)
    df['value_isforbidden'] = df['message'].apply(value_isforbidden)
    df['value_isFail'] = df['message'].apply(value_isFail)
    df['key_script_not_found'] = df['message'].apply(key_script_not_found)
    df['key_isFatal'] = df['message'].apply(key_isFatal)
    df['key_isscandir'] = df['message'].apply(key_isscandir)

    df['level_isError'] = df['level'].apply(level_isError)
    return df

    
def process_apache_error(df):  # Replace 'your_regex_pattern_here' with your actual regex pattern

    return df
######################################################for apache access #########################################

##########################################for apache error####################################################

    

###############################################################################################################
def process_rdd(path):
    df=pd.read_json(path,lines=True)
    print("enter check")
    start_time_process = time.time()
    print("***** phase 1 apache_error log seperation ******")
    df=process_apache_error(df)
            
    start_time_dns = time.time()
    # dataframes['dnsmasq'].show()
    unique_owners=df['owner'].unique()
            # unique_owners.show()
    print("Phase 1 - Completed")
            
    end_time_dns = time.time()

    elapsed_time1 = end_time_dns - start_time_dns
    print("log seperation time <apache_error_phase_1>:", elapsed_time1, "seconds\n")

        #############LET's seperate by log owner#################################
            
    print("***** phase 2 apache_error owner seperation & furthur pre-processing ******")
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
            print(f"Pre-processed time <apache_error_phase_2_{owner}>:", elapsed_time2, "seconds\n")

                    # send to anomaly module
            print("***** phase 3 apache_error  anomaly detection ******")
            
            start_time_dns = time.time()
            df_pyspark = process_apache_error_for_pred(df_pyspark) 
            list_of_columns = [
                'client',
                'key_isAH',
                'value_isInvalid',
                'value_isforbidden',
                'value_isFail',
                'key_script_not_found',
                'key_isFatal',
                'key_isscandir',
                'level_isError',
                'label'
                ]
            df_pyspark=df_pyspark[list_of_columns]
            df_pyspark['prediction']=loaded_rf_model_apache_error.predict(df_pyspark)
            count_ones = df_pyspark['prediction'].eq(1).sum()
            count_zeros = df_pyspark['prediction'].eq(0).sum()

            print(f"Count of 1s: {count_ones}")
            print(f"Count of 0s: {count_zeros}")
            print("Phase 3 - Prediction Ended")
            end_time_dns = time.time()
            elapsed_time4 = end_time_dns - start_time_dns
            print(f"Anomaly detection time <apache_error_phase_4_{owner}>:", elapsed_time4, "seconds\n")
                    ########################
            print("*********************************** END ***********************************\n")
            print("Pre-processed time <apache_error_phase_1>:", elapsed_time1, "seconds\n")
            print(f"Pre-processed time <apache_error_phase_2_{owner}>:", elapsed_time2, "seconds\n")
            print(f"Anomaly detection time <apache_error_phase_3_{owner}>:", elapsed_time4, "seconds\n")
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

process_rdd("s3://siemtest22/siem_spark_model/eval_data2/apache2_error_normalized_client3_256000.json/part-00000-6bedb3a8-2eb7-40c1-811f-26bc9ec22c47-c000.json")
                        




