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
indexer_dnsmasq = './Indexer_no_spark/key_value_list.txt'
model_path='./model/ML_trained_model2/DNS_rf_model.pkl'
# indexer_error = StringIndexerModel.read().load("s3://siemtest22/siem_spark_model/siem dev2/model/indexer_apacheerror")
################################################################################
loaded_rf_model_dnsmasq=joblib.load(model_path)
################regex for building key-value ######################################################################
dnsmasq_regex = r"([a-z]+\[?[A-Z]*\]?)\s(\S+)\s([fromtois]+)\s(\S+)"
error_regex_final_maybe=r"([^:']+:?)(('[^']+')?(\snot found or unable to stat))?(\s*([^\/:,'\(]+:?[^:\/,'\(]+:?)\s*(.*?(?=, referer|$)))?((, referer:)(.*))?"
###########################################################################################################




###########################################for dnsmasq#########################################################
def categorize_ip(value2):
    try:
        # Split IP address into octets
        octets = list(map(int, value2.split('.')))

        # Check if IPv4 is private
        if (octets[0] == 10) or (octets[0] == 172 and 16 <= octets[1] <= 31) or (octets[0] == 192 and octets[1] == 168):
            return 0  # IPv4 private
        else:
            return 1  # IPv4 public
    except:
        try:
            # Split IP address into parts
            parts = value2.split(':')

            # Check if IPv6 is private
            if parts[0] == 'fd':
                return 2  # IPv6 private
            else:
                # Check if parts[1] has a value or an empty string
                if parts[2] or parts[2] == '':
                    return 3  # IPv6 public
                else:
                    return 4  # Non-IP values
        except:
            return 4  # Non-IP values

    
def count_dots(s):
    return s.count('.')

def count_hyphens(s):
    return s.count('-')

def count_slash(s):
    return s.count('/')

def count_asterisk(s):
    return s.count('*')

def count_capitals(value):
    return sum(1 for c in value if c.isupper())

def has_microsoft_extension(value):
    microsoft_extensions = ['doc', 'docx', 'odt', 'pages', 'rtf', 'txt', 'wpd', 'wps',
                            'csv', 'numbers', 'ods', 'xls', 'xlsx',
                            'asp', 'aspx', 'css', 'htm', 'html', 'jsp', 'php', 'xml',
                            'afdesign', 'ai', 'cad', 'cdr', 'drw', 'dwg', 'eps', 'odg', 'svg', 'vsdx',
                            'afpub', 'indd', 'pdf', 'pdfxml', 'pmd', 'pub', 'qxp',
                            'c', 'cpp', 'cs', 'java', 'js', 'json', 'py', 'sql', 'swift', 'vb',
                            '7z', 'rar', 'tar', 'tar.gz', 'zip',
                            'bak', 'cfg', 'conf', 'ini', 'msi', 'sys', 'tmp',
                            'app', 'bat', 'bin', 'cmd', 'com', 'exe', 'vbs', 'x86']
    words = value.split('.')
    for word in words:
        if word.lower() in microsoft_extensions:
            return 1
    return 0


def calculate_entropy(value):
    counts = {}
    total_count = 0
    for c in value:
        counts[c] = counts.get(c, 0) + 1
        total_count += 1
    probabilities = [count / total_count for count in counts.values()]
    entropy_value = sum(-p * math.log2(p) for p in probabilities)
    return entropy_value

def is_human_readable(entropy_value, threshold=5.0):
    return 1 if entropy_value < threshold else 0
def process_dnsmasq_for_pred(df):
    df['encoded_key'] = df['encoded_key'].astype(int)
    df['key_length'] = df['key'].apply(len)
    df['value1_length'] = df['value1'].apply(len)
    df['value2_length'] = df['value2'].apply(len)

    df['value1_dot_count'] = df['value1'].apply(count_dots)
    df['value1_hyphen_count'] = df['value1'].apply(count_hyphens)
    df['value1_slash_count'] = df['value1'].apply(count_slash)
    df['value1_asterisk_count'] = df['value1'].apply(count_asterisk)
    df['value1_capital_count'] = df['value1'].apply(count_capitals)
    df['value1_has_file_extensions'] = df['value1'].apply(has_microsoft_extension)
    df['entropy'] = df['value1'].apply(calculate_entropy)
    df['value1_human_readable'] = df['entropy'].apply(is_human_readable)

    df['value2_dot_count'] = df['value2'].apply(count_dots)
    df['value2_hyphen_count'] = df['value2'].apply(count_hyphens)
    df['value2_slash_count'] = df['value2'].apply(count_slash)
    df['value2_asterisk_count'] = df['value2'].apply(count_asterisk)
    df['value2_capital_count'] = df['value2'].apply(count_capitals)
    df['value2_has_file_extensions'] = df['value2'].apply(has_microsoft_extension)
    df['value2_ip_class'] = df['value2'].apply(categorize_ip)
    return df
def custom_string_indexer(df):
    with open(indexer_dnsmasq, 'r') as file:
        file_content = file.readlines()

    key_value_list = [line.strip().split(',') for line in file_content]

    columns_to_encode = ['key']
    for column in columns_to_encode:
        # Create a mapping dictionary from key_value_list
        mapping_dict = {value: index for index, value in enumerate(key_value_list[columns_to_encode.index(column)])}
        # Apply the mapping to the DataFrame column
        df['encoded_key'] = df[column].map(mapping_dict)
        # Update key_value_list with new values
        new_values = df[column][~df[column].isin(key_value_list[columns_to_encode.index(column)])].unique()
        key_value_list[columns_to_encode.index(column)].extend(new_values)
        return df
    
def process_dnsmasq(df):  # Replace 'your_regex_pattern_here' with your actual regex pattern
    # Define functions to extract values from message
    def extract_response(message):
        match = re.search(dnsmasq_regex, message)
        return match.group(1) if match else ''
    def extract_domain(message):
        match = re.search(dnsmasq_regex, message)
        return match.group(2) if match else ''
    def extract_term(message):
        match = re.search(dnsmasq_regex, message)
        return match.group(3) if match else ''
    def extract_ip_addr(message):
        match = re.search(dnsmasq_regex, message)
        return match.group(4) if match else ''
    def concat_key(response, term):
        if response is None:
            response=""
        if term is None:
            term=""
        return f"{response} <*> {term} <*>"
    def concat_time(time):
        return f"{time} 2022"
    # Apply functions to extract values and create DataFrame# Assuming filtered_data is a list of tuples or lists
    
    df['response'] = df['message'].apply(extract_response)
    df['domain'] = df['message'].apply(extract_domain)
    df['term'] = df['message'].apply(extract_term)
    df['ip_addr'] = df['message'].apply(extract_ip_addr)
    df['key'] = df.apply(lambda x: concat_key(x['response'], x['term']), axis=1)
    df['value1'] = df['domain']
    df['value2'] = df['ip_addr']
    df['time'] = df['time'].apply(concat_time)
    
    # Convert 'time' column to epoch_timestamp
    df['epoch_timestamp'] = pd.to_datetime(df['time'], format='%b %d %H:%M:%S %Y')
    df['epoch_timestamp']=df['epoch_timestamp'].astype('int64') 
    df['epoch_timestamp']=df['epoch_timestamp'].div(10**9)
    df['owner']=df['owner']
    
    # Drop unnecessary columns
    df_indexed=custom_string_indexer(df)
    df_indexed = df_indexed.drop(columns=['message', 'domain', 'term', 'ip_addr', 'time'])
    
    return df
######################################################for apache access #########################################

##########################################for apache error####################################################

    

###############################################################################################################
def process_rdd(path):
    df=pd.read_json(path,lines=True)
    print("enter check")
    start_time_process = time.time()
    print("***** phase 1 dnsmasq log seperation ******")
    df=process_dnsmasq(df)
            
    start_time_dns = time.time()
    # dataframes['dnsmasq'].show()
    unique_owners=df['owner'].unique()
            # unique_owners.show()
    print("Phase 1 - Completed")
            
    end_time_dns = time.time()

    elapsed_time1 = end_time_dns - start_time_dns
    print("log seperation time <dnsmasq_phase_1>:", elapsed_time1, "seconds\n")

        #############LET's seperate by log owner#################################
            
    print("***** phase 2 dnsmasq owner seperation & furthur pre-processing ******")
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
            print(f"Pre-processed time <dnsmasq_phase_2_{owner}>:", elapsed_time2, "seconds\n")

                    # send to anomaly module
            print("***** phase 3 dnsmasq  anomaly detection ******")
            
            start_time_dns = time.time()
            df_pyspark = process_dnsmasq_for_pred(df_pyspark) 
            list_of_columns = [
                    'encoded_key',
                    'key_length',
                    'value1_length',
                   'value2_length',
                    'value1_dot_count',
                    'value1_hyphen_count',
                    'value1_slash_count',
                    'value1_asterisk_count',
                    'value1_capital_count',
                    'value1_has_file_extensions',
                    'value1_human_readable',
                    'value2_dot_count',
                    'value2_hyphen_count',
                    'value2_slash_count',
                    'value2_asterisk_count',
                    'value2_capital_count',
                    'value2_has_file_extensions',
                    'value2_ip_class'
                    ]
            df_pyspark=df_pyspark[list_of_columns]
            df_pyspark['prediction']=loaded_rf_model_dnsmasq.predict(df_pyspark)
            count_ones = df_pyspark['prediction'].eq(1).sum()
            count_zeros = df_pyspark['prediction'].eq(0).sum()

            print(f"Count of 1s: {count_ones}")
            print(f"Count of 0s: {count_zeros}")
            print("Phase 3 - Prediction Ended")
            end_time_dns = time.time()
            elapsed_time4 = end_time_dns - start_time_dns
            print(f"Anomaly detection time <dnsmasq_phase_4_{owner}>:", elapsed_time4, "seconds\n")
                    ########################
            print("*********************************** END ***********************************\n")
            print("Pre-processed time <dnsmasq_phase_1>:", elapsed_time1, "seconds\n")
            print(f"Pre-processed time <dnsmasq_phase_2_{owner}>:", elapsed_time2, "seconds\n")
            print(f"Anomaly detection time <dnsmasq_phase_3_{owner}>:", elapsed_time4, "seconds\n")
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
    "s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2_500.json/part-00000-51e79c96-dfad-4cb9-8387-f761ed07da1a-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2_1000.json/part-00000-0811eaa8-9414-4b5c-bc11-0ca5160f384e-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2_2000.json/part-00000-03e22c72-d396-4d8f-b15a-79ebae4c69f5-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2_4000.json/part-00000-c631097d-b8e5-481f-b99d-891770667b58-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2_8000.json/part-00000-f9ce37e9-3f1a-4af1-a7f9-6bff06dc09ae-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2_16000.json/part-00000-2586894d-608f-473c-b70b-93919ab48d37-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2_32000.json/part-00000-81b2bbc9-6157-432c-ad52-8b11cbedab8c-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2_64000.json/part-00000-7ea1c786-a826-4735-a11c-70948baba60c-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2_128000.json/part-00000-12b4f811-435f-48e7-a371-f9cb502ca53c-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2_256000.json/part-00000-6a98527c-1963-42d6-bbe5-d47a987e764b-c000.json",
    "s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2_512000.json/part-00000-201217.json",
    "s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2_1024000.json/part-00000-57557.json",
    "s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2_2048000.json/part-00000-5105.json"
    ]
for i in list_spark:
    process_rdd(i)
                        



