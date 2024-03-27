from pyspark import SparkContext
from pyspark.streaming import StreamingContext
from pyspark.streaming.kinesis import KinesisUtils, InitialPositionInStream
from pyspark.sql.functions import col,regexp_extract,concat,lit,array,unix_timestamp,when,row_number,from_unixtime, substring,monotonically_increasing_id
from pyspark.sql import Row
from pyspark.sql import SparkSession
import json 
from pyspark.ml.feature import StringIndexer,StringIndexerModel,VectorAssembler
from pyspark.conf import SparkConf
from rule_base.rules import Apache_error,Dnsmasq
import numpy as np
import time

### For Phase 4 ###
from pyspark.sql.functions import from_unixtime, col, unix_timestamp, expr,lag,round,dayofweek,length,regexp_replace,count, desc,udf
from pyspark.sql.window import Window
from pyspark.sql.types import IntegerType,FloatType
import math
from pyspark.ml.classification import RandomForestClassificationModel


###############################require configuration for aws 
conf = (
    SparkConf()
    .setAppName("KInesisTest") \
    .set("spark.hadoop.fs.s3a.endpoint", "s3.amazonaws.com") \
    .set("spark.hadoop.fs.s3a.access.key", "ACCESS_KEY") \
    .set("spark.hadoop.fs.s3a.secret.key", "SECRET_ACCESS_KEY") \
    .set("spark.sql.shuffle.partitions", "10") \
)

spark = SparkSession.builder.config(conf=conf).getOrCreate()
sc = spark.sparkContext
sc.setLogLevel("ERROR")
ssc = StreamingContext(sc, 10)

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
indexer_dnsmasq = StringIndexerModel.read().load("s3://siemtest22/siem_spark_model/siem dev2/model/indexer_dnsmasq")
indexer_error = StringIndexerModel.read().load("s3://siemtest22/siem_spark_model/siem dev2/model/indexer_apacheerror")
################################################################################

################regex for building key-value ######################################################################
dnsmasq_regex = r"([a-z]+\[?[A-Z]*\]?)\s(\S+)\s([fromtois]+)\s(\S+)"
error_regex_final_maybe=r"([^:']+:?)(('[^']+')?(\snot found or unable to stat))?(\s*([^\/:,'\(]+:?[^:\/,'\(]+:?)\s*(.*?(?=, referer|$)))?((, referer:)(.*))?"
###########################################################################################################

def process_dnsmasq(filtered_rdd):
    #fix timestamp, create key, create value
    df=spark.createDataFrame(filtered_rdd)
    df=df.withColumn("response", regexp_extract("message", dnsmasq_regex, 1)) \
    .withColumn("domain", regexp_extract("message", dnsmasq_regex, 2)) \
    .withColumn("term", regexp_extract("message", dnsmasq_regex, 3)) \
    .withColumn("ip_addr", regexp_extract("message", dnsmasq_regex, 4)) \
    .withColumn("key", concat("response", lit(" <*> "),"term", lit(" <*>"))) \
    .withColumn("value1", regexp_extract("message", dnsmasq_regex, 2)) \
    .withColumn("value2", regexp_extract("message", dnsmasq_regex, 4)) \
    .withColumn("time", concat("time", lit(" 2022"))) \
    .withColumn("epoch_timestamp", unix_timestamp("time", "MMM dd HH:mm:ss yyyy")) 
    df_indexed=indexer_dnsmasq.transform(df)
    df_indexed=df_indexed.drop("pid","time","domain","term","ip_addr")
    return df_indexed


def process_apache_error(filtered_rdd):
    df=spark.createDataFrame(filtered_rdd)
    df=df.withColumn("entity", regexp_extract("message", error_regex_final_maybe,1)) \
    .withColumn("script_path", regexp_extract("message", error_regex_final_maybe,3)) \
    .withColumn("not_found_msg",regexp_extract('message', error_regex_final_maybe,4)) \
    .withColumn("error_apache",regexp_extract('message', error_regex_final_maybe,6)) \
    .withColumn("error_apache_path",regexp_extract('message', error_regex_final_maybe,7)) \
    .withColumn("referer",regexp_extract('message', error_regex_final_maybe,9)) \
    .withColumn("referer_msg",regexp_extract("message",error_regex_final_maybe,10)) \
    .withColumn("key", concat("entity",lit(" "),"error_apache",lit("<*>"),"not_found_msg","referer")) \
    .withColumn("epoch_timestamp", unix_timestamp("time", "MMM dd HH:mm:ss.SSSSSS yyyy")) \
    .withColumn("value",array("script_path","error_apache_path","referer_msg"))

    df=df.withColumn("key",concat("key",
                                            when(
                                                df.referer == ", referer:", lit("<*>")).otherwise(lit(""))))
    df=df.drop("script_path",'not_found_msg',"error_apache",'error_apache_path','referer',"referer_msg","time","pid")
    df_indexed=indexer_error.transform(df)
    return df_indexed

def process_apache2_access(filtered_rdd):
    df=spark.createDataFrame(filtered_rdd)
    return df


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


def process_dnsmasq_for_pred(df_pyspark):
    # df_pyspark = df_pyspark.drop("ident", "log_format", "owner", "message")  # Remove unnecessary columns
    df_pyspark = df_pyspark.withColumn("encoded_key", col("encoded_key").cast("int"))
    df_pyspark = df_pyspark.withColumn("key_length", length("key"))

    # df_pyspark = df_pyspark.withColumn("timestamp_datetime", from_unixtime("epoch_timestamp").cast("timestamp"))
    # lag_col = lag(col("epoch_timestamp")).over(Window.orderBy("epoch_timestamp"))
    # df_pyspark = df_pyspark.withColumn("time_diff_unix", round((col("epoch_timestamp") - lag_col), 1))
    # df_pyspark = df_pyspark.fillna(0, subset=["time_diff_unix"])
    # df_pyspark = df_pyspark.withColumn("time_diff_unix", col("time_diff_unix").cast("decimal(10,1)"))
    # df_pyspark = df_pyspark.withColumn("day_of_week", dayofweek("timestamp_datetime"))
    
    df_pyspark = df_pyspark.withColumn("value1_length", length("value1"))
    df_pyspark = df_pyspark.withColumn("value2_length", length("value2"))

    count_dots_udf = udf(count_dots, IntegerType())
    count_hyphens_udf = udf(count_hyphens, IntegerType())
    count_slash_udf = udf(count_slash, IntegerType())
    count_asterisk_udf = udf(count_asterisk, IntegerType())
    
    df_pyspark = df_pyspark.withColumn("value1_dot_count", count_dots_udf("value1"))
    df_pyspark = df_pyspark.withColumn("value1_hyphen_count", count_hyphens_udf("value1"))
    df_pyspark = df_pyspark.withColumn("value1_slash_count", count_slash_udf("value1"))
    df_pyspark = df_pyspark.withColumn("value1_asterisk_count", count_asterisk_udf("value1"))

    count_capitals_udf = udf(count_capitals, IntegerType())
    df_pyspark = df_pyspark.withColumn("value1_capital_count", count_capitals_udf(col("value1")))

    has_microsoft_extension_udf = udf(has_microsoft_extension, IntegerType())
    df_pyspark = df_pyspark.withColumn("value1_has_file_extensions", has_microsoft_extension_udf(col("value1")))

    calculate_entropy_udf = udf(calculate_entropy, FloatType())
    is_human_readable_udf = udf(is_human_readable, IntegerType())
    df_pyspark = df_pyspark.withColumn("entropy", calculate_entropy_udf(col("value1"))) # Pending to DROP
    df_pyspark = df_pyspark.withColumn("value1_human_readable", is_human_readable_udf(col("entropy")))

    ###########

    df_pyspark = df_pyspark.withColumn("value2_dot_count", count_dots_udf("value2"))
    df_pyspark = df_pyspark.withColumn("value2_hyphen_count", count_hyphens_udf("value2"))
    df_pyspark = df_pyspark.withColumn("value2_slash_count", count_slash_udf("value2"))
    df_pyspark = df_pyspark.withColumn("value2_asterisk_count", count_asterisk_udf("value2"))

    count_capitals_udf = udf(count_capitals, IntegerType())
    df_pyspark = df_pyspark.withColumn("value2_capital_count", count_capitals_udf(col("value2")))

    has_microsoft_extension_udf = udf(has_microsoft_extension, IntegerType())
    df_pyspark = df_pyspark.withColumn("value2_has_file_extensions", has_microsoft_extension_udf(col("value2")))

    # window_spec_value1 = Window().orderBy("value1")
    # window_spec_value2 = Window().orderBy("value2")
    
    # df_pyspark = df_pyspark.withColumn("value1_count", count("value1").over(window_spec_value1))
    # df_pyspark = df_pyspark.withColumn("value2_count", count("value2").over(window_spec_value2))

    # Register the UDF
    categorize_ip_udf = udf(categorize_ip, IntegerType())
    
    # Apply the UDF to create a new column 'ip_category'
    df_pyspark = df_pyspark.withColumn("value2_ip_class", categorize_ip_udf("value2"))
    list_of_columns = [
        "response",
        "value1",
        "value2",
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
        'value2_ip_class',
       
    ]
# Assuming df is your DataFrame
# df_label = df_pyspark.select(['label'])
    df_pyspark = df_pyspark.select(*list_of_columns)

    
    return df_pyspark

######################################################for apache access #########################################
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
    if value is not None and (value.startswith('/.') or value.startswith('/~') or value.startswith('/_')):
        return 1
    else:
        return 0


def count_slash(s):
    if s is not None:
        return s.count('/')
    else:
        return 0

def has_special_char_in_path(value):
    characters = ['%', '&', '=', '?']
    if value is not None and any(char in value for char in characters):
        return 1
    else:
        return 0

# request method
def encode_method(value, values_list = ['-', 'OPTIONS', 'HEAD', 'GET','POST']):
    try:
        return values_list.index(value)
    except ValueError:
        return -1  # Return -1 if value is not found in the list   
def process_apacheaccess_for_pred(df_pyspark):
    check_agent_udf = udf(check_agent, IntegerType())
    df_pyspark = df_pyspark.withColumn("check_agent", check_agent_udf("agent"))

    code_ext_udf = udf(code_ext, IntegerType())
    df_pyspark = df_pyspark.withColumn("code_ext", code_ext_udf("code"))

    hidden_dir_udf = udf(hidden_dir, IntegerType())
    df_pyspark = df_pyspark.withColumn("hidden_dir", hidden_dir_udf("path"))

    count_slash_udf = udf(count_slash, IntegerType())
    df_pyspark = df_pyspark.withColumn("count_slash", count_slash_udf("path"))



    # Truncate timestamp to second
    df_pyspark = df_pyspark.withColumn("timestamp_second", substring(col("time").cast("string"), 1, 19))

    # Assign unique IDs to each row
    df_pyspark = df_pyspark.withColumn("id", monotonically_increasing_id())

    # Group by host and truncated timestamp, count entries
    df_grouped = df_pyspark.groupBy("host", "timestamp_second").count().withColumnRenamed("count", "entries_in_second")

    # Join grouped DataFrame with original data DataFrame
    df_pyspark = df_pyspark.join(df_grouped, ['host', 'timestamp_second'], 'left_outer')
    

    # Sort the resulting DataFrame based on IDs
    # df_pyspark = df_result.sort("id")



    has_special_char_in_path_udf = udf(has_special_char_in_path, IntegerType())
    df_pyspark = df_pyspark.withColumn("has_special_char_in_path", has_special_char_in_path_udf("path"))

    df_pyspark = df_pyspark.withColumn("size_int", col("size").cast("int"))

    encode_method_udf = udf(encode_method, IntegerType())
    df_pyspark = df_pyspark.withColumn("encode_method", encode_method_udf("method"))
    return df_pyspark
##########################################for apache error####################################################
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

def process_apache_error_for_pred(df_pyspark):
    key_isAH_udf = udf(key_isAH, IntegerType())
    df_pyspark = df_pyspark.withColumn("key_isAH", key_isAH_udf("message"))

    value_isInvalid_udf = udf(value_isInvalid, IntegerType())
    df_pyspark = df_pyspark.withColumn("value_isInvalid", value_isInvalid_udf("message"))

    value_isforbidden_udf = udf(value_isforbidden, IntegerType())
    df_pyspark = df_pyspark.withColumn("value_isforbidden", value_isforbidden_udf("message"))

    value_isFail_udf = udf(value_isFail, IntegerType())
    df_pyspark = df_pyspark.withColumn("value_isFail", value_isFail_udf("message"))

    key_script_not_found_udf = udf(key_script_not_found, IntegerType())
    df_pyspark = df_pyspark.withColumn("key_script_not_found", key_script_not_found_udf("message"))

    key_isFatal_udf = udf(key_isFatal, IntegerType())
    df_pyspark = df_pyspark.withColumn("key_isFatal", key_isFatal_udf("message"))

    key_isscandir_udf = udf(key_isscandir, IntegerType())
    df_pyspark = df_pyspark.withColumn("key_isscandir", key_isscandir_udf("message"))

    level_isError_udf = udf(level_isError, IntegerType())
    df_pyspark = df_pyspark.withColumn("level_isError", level_isError_udf("level"))

    return df_pyspark
    

###############################################################################################################
def process_rdd(rdd):
    print("enter check")
    start_time_process = time.time()
    if not rdd.isEmpty():
        print("not empty")
        dataframes = {}
        json_rdd = rdd.map(lambda x: json.loads(x))
        apache_error = json_rdd.filter(lambda x: x.get('log_format') == 'apache_error')
        dnsmasq_rdd = json_rdd.filter(lambda x: x.get('log_format') == 'dnsmasq')
        apache2_access=json_rdd.filter(lambda x:x.get('log_format')=="apache2_access")

        if not apache_error.isEmpty():
            print("***** phase 1 apache error log seperation ******")
            start_time_error = time.time()
            
            dataframes['apache_error'] = process_apache_error(apache_error)
            # dataframes['apache_error'].show()
            end_time_error = time.time()
            elapsed_time1 = end_time_error - start_time_error
            print("log seperation time <Apache_error_phase_1>:", elapsed_time1, "seconds\n")

            unique_owners=dataframes['apache_error'].select('owner').distinct()
            #############LET's seperate by log owner#################################
            print("***** phase 2 apache error owner seperation ******")
            for row in unique_owners.collect():
                    # since only 1 column is collected , so it's always at row[0]
                    start_time_error = time.time()
                    unique_value = row[0]
                    df_temp = dataframes['apache_error'].filter(dataframes['apache_error']['owner'] == unique_value)
                    df_temp.show()
                    # send to anomaly module
                    end_time_dns = time.time()

                    elapsed_time2 = end_time_dns - start_time_dns
                    print("log seperation time <apache_error_phase_2>:", elapsed_time2, "seconds\n")
                    print("***** phase 3 apache error  anomaly detection ******")
                    start_time_error = time.time()
                    df_pyspark=process_apache_error_for_pred(df_pyspark)
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
                    ]
                    vector_assembler=VectorAssembler(inputCols=list_of_columns, outputCol="features")
                    df_pyspark=vector_assembler.transform(df_pyspark)
                    df_pyspark=loaded_rf_model_error.transform(df_pyspark)
                    df_pyspark.collect()
                    end_time_error = time.time()
                    elapsed_time3 = start_time_error - end_time_error
                    print(f"Anomaly detection time <apache_error_phase_3_{owner}>:", elapsed_time4, "seconds\n")
                    ########################
                    print("*********************************** END ***********************************\n")
                    print("Pre-processed time <apache_error_phase_1>:", elapsed_time1, "seconds\n")
                    print(f"Pre-processed time <apache_error_phase_2_{owner}>:", elapsed_time2, "seconds\n")
                    print(f"Anomaly detection time <apche_error_phase_3_{owner}>:", elapsed_time3, "seconds\n")


                    ######################

        if not dnsmasq_rdd.isEmpty():
            print("***** phase 1 dnsmasq log seperation ******")
            
            start_time_dns = time.time()

            dataframes['dnsmasq'] = process_dnsmasq(dnsmasq_rdd)
            # dataframes['dnsmasq'].show()
            unique_owners=dataframes['dnsmasq'].select('owner').distinct()
            # unique_owners.show()
            print("Phase 1 - Completed")
            
            end_time_dns = time.time()

            elapsed_time1 = end_time_dns - start_time_dns
            print("log seperation time <dnsmasq_phase_1>:", elapsed_time1, "seconds\n")

            #############LET's seperate by log owner#################################
            
            print("***** phase 2 dnsmasq owner seperation & furthur pre-processing ******")
            for row in unique_owners.collect():
                    
                    start_time_dns = time.time()

                    # since only 1 column is collected , so it's always at row[0]
                    owner = row[0]
                    df_temp = dataframes['dnsmasq'].filter(dataframes['dnsmasq']['owner'] == owner)
                    # owner = df_temp.select("owner").first()[0]
                    # df_temp.show()
                    print("Phase 2 - Completed")
                    df_pyspark = df_temp.alias("df_pyspark")
               
                   

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
                    vector_assembler=VectorAssembler(inputCols=list_of_columns, outputCol="features")
                    df_pyspark=vector_assembler.transform(df_pyspark)
                    df_pyspark=loaded_rf_model_dnsmasq.transform(df_pyspark)
                    # df_pyspark = df_pyspark.withColumn("prediction", predict_data(*list_of_columns))
                    # df_pyspark.show()
                    df_pyspark.agg(count(when(col('prediction')==1,1)),count(when(col('prediction')==0,0))).show()
                    print("Phase 3 - Prediction Ended")
                    end_time_dns = time.time()
                    elapsed_time4 = end_time_dns - start_time_dns
                    print(f"Anomaly detection time <dnsmasq_phase_4_{owner}>:", elapsed_time4, "seconds\n")
                    ########################
                    print("*********************************** END ***********************************\n")
                    print("Pre-processed time <dnsmasq_phase_1>:", elapsed_time1, "seconds\n")
                    print(f"Pre-processed time <dnsmasq_phase_2_{owner}>:", elapsed_time2, "seconds\n")
                    print(f"Anomaly detection time <dnsmasq_phase_3_{owner}>:", elapsed_time4, "seconds\n")

       

                    
           
            # dataframes['dnsmasq'].write.mode('overwrite').parquet("C:\\Users\\A570ZD\\Desktop\\kinesis_stream\\temp\\dnsmasq") 
        if not apache2_access.isEmpty():
            print("***** phase 1 apache2 access log seperation ******")
            start_time_access = time.time()
            dataframes['apache2_access']=process_apache2_access(apache2_access)
            unique_owners=dataframes['apache2_access'].select('owner').distinct()
            # unique_owners.show()
            end_time_access = time.time()

            elapsed_time1 = end_time_access - start_time_access
            print("log seperation time <apacheaccess_phase_1>:", elapsed_time1, "seconds\n")

            
            #############LET's seperate by log owner#################################
            
            print("***** phase 2 apache2 access owner seperation ******")
            for row in unique_owners.collect():
                    start_time_access = time.time()
                    
                    # since only 1 column is collected , so it's always at row[0]
                    owner = row[0]
                    df_temp = dataframes['apache2_access'].filter(dataframes['apache2_access']['owner'] == owner)
                    df_pyspark = df_temp.alias("df_pyspark")

                    # df_pyspark.show()
                    end_time_access = time.time()
                    elapsed_time2 = end_time_access - start_time_access
                    print(f"Pre-processed time <apacheacess_phase_2_{owner}>:", elapsed_time2, "seconds\n")
                    
                    print("***** phase 3 apache access  anomaly detection ******")
                
                    df_pyspark = df_pyspark.withColumn('time', unix_timestamp('time', "dd/MMM/yyyy:HH:mm:ss Z"))
                    df_pyspark=df_pyspark[~(df_pyspark['agent'].isNull())]

                    df_pyspark=process_apacheaccess_for_pred(df_pyspark)
                    start_time_access = time.time()
                    list_of_columns = [
                        'check_agent',
                        'code_ext',
                        'hidden_dir',
                        'count_slash',
                        'entries_in_second',
                        'size_int',
                        'has_special_char_in_path',
                        'encode_method',
                    ]
                    vector_assembler=VectorAssembler(inputCols=list_of_columns, outputCol="features")
                    df_pyspark=vector_assembler.transform(df_pyspark)
                    df_pyspark=loaded_rf_model_access.transform(df_pyspark)
                    df_pyspark.show()
                    end_time_access = time.time()
                    df_pyspark.agg(count(when(col('prediction')==1,1)),count(when(col('prediction')==0,0))).show()
                    elapsed_time4 = end_time_access - start_time_access
                    print(f"Anomaly detection time <apache_access_phase_3_{owner}>:", elapsed_time4, "seconds\n")

                    ##################
                    print("*********************************** END ***********************************\n")
                    print("Pre-processed time <apache_access_phase_1>:", elapsed_time1, "seconds\n")
                    print(f"Pre-processed time <apache_access_phase_2_{owner}>:", elapsed_time2, "seconds\n")
                    print(f"Anomaly detection time <apache_access_phase_3_{owner}>:", elapsed_time4, "seconds\n")
                    
        end_time_process = time.time()
        elapsed_time_process = end_time_process - start_time_process
        print("Summary - time taken:")
        print("Overall elapsed time <kinesis_test.py>:", elapsed_time_process, "seconds\n")

# TEST DATA
# data=[
# '{"time":"Jan 18 10:07:23.284717 2022","log_format":"apache_error","owner":"client01","level":"php7:warn","pid":"27406","client":"10.35.35.206:32894","message":"PHP Warning:  scandir(/var/www/intranet.price.fox.org/wp-content/uploads/wpdiscuz/cache/gravatars/): failed to open dir: No such file or directory in /var/www/intranet.price.fox.org/wp-content/plugins/wpdiscuz/utils/class.WpdiscuzCache.php on line 190"}',
# '{"time":"Jan 18 10:07:23.284843 2022","log_format":"apache_error","owner":"client01","level":"php7:warn","pid":"27406","client":"10.35.35.206:32894","message":"PHP Warning:  scandir(): (errno 2): No such file or directory in /var/www/intranet.price.fox.org/wp-content/plugins/wpdiscuz/utils/class.WpdiscuzCache.php on line 190"}',
# '{"time":"Jan 18 12:17:52.008720 2022","log_format":"apache_error","owner":"client01","level":"php7:error","pid":"28411","client":"172.17.130.196:55206","message":"script \'/var/www/intranet.price.fox.org/searchreplacedb2.php\' not found or unable to stat, referer: https://intranet.price.fox.org"}',
# '{"time":"Jan 18 12:17:52.452415 2022","log_format":"apache_error","owner":"client01","level":"autoindex:error","pid":"28490","client":"172.17.130.196:55208","message":"AH01276: Cannot serve directory /var/www/intranet.price.fox.org/wp-content/uploads/: No matching DirectoryIndex (index.html,index.cgi,index.pl,index.php,index.xhtml,index.htm) found, and server-generated directory index forbidden by Options directive, referer: https://intranet.price.fox.org"}',
# '{"time":"Jan 18 12:17:52.466276 2022","log_format":"apache_error","owner":"client01","level":"php7:error","pid":"28490","client":"172.17.130.196:55208","message":"script \'/var/www/intranet.price.fox.org/emergency.php\' not found or unable to stat, referer: https://intranet.price.fox.org"}',
# '{"host":"172.17.130.196","owner":"client01","log_format":"apache2_access","user":"-","method":"GET","path":"/","code":"200","size":"6128","referer":"-","agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/95.0.4638.69 Safari/537.36"}',
# '{"host":"172.17.130.196","owner":"client01","log_format":"apache2_access","user":"-","method":"GET","path":"/wp-includes/css/dist/block-library/style.min.css?ver=5.8.3","code":"200","size":"10846","referer":"http://intranet.price.fox.org/","agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/95.0.4638.69 Safari/537.36"}',
# '{"host":"172.17.130.196","owner":"client01","log_format":"apache2_access","user":"-","method":"GET","path":"/wp-content/themes/go/dist/css/design-styles/style-traditional.min.css?ver=1.5.1","code":"200","size":"1489","referer":"http://intranet.price.fox.org/","agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/95.0.4638.69 Safari/537.36"}',
# '{"host":"172.17.130.196","owner":"client01","log_format":"apache2_access","user":"-","method":"GET","path":"/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.3.2","code":"200","size":"4505","referer":"http://intranet.price.fox.org/","agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/95.0.4638.69 Safari/537.36"}',
# '{"time":"Jan 21 00:01:44","ident":"dnsmasq","owner":"client01","log_format":"dnsmasq","pid":"3468","message":"query[A] 3x6-.602-.OgEWPzRasaBfzw*1YgPwvfpK5ndYxfeL6t-.AAWCJrJfzqWHDvNtdSStYg3cnHaa0NHOxM-.26JBAO6h3xFvABN5REohh3RObsbew4lIQs-.XDxHdPvCAsmEqutMHFanKav*p1u36CvjZ4-.customers_2017.xlsx.email-19.kennedy-mendoza.info from 10.143.0.103"}',
# '{"time":"Jan 21 00:01:44","ident":"dnsmasq","owner":"client01","log_format":"dnsmasq","pid":"3468","message":"forwarded 3x6-.602-.OgEWPzRasaBfzw*1YgPwvfpK5ndYxfeL6t-.AAWCJrJfzqWHDvNtdSStYg3cnHaa0NHOxM-.26JBAO6h3xFvABN5REohh3RObsbew4lIQs-.XDxHdPvCAsmEqutMHFanKav*p1u36CvjZ4-.customers_2017.xlsx.email-19.kennedy-mendoza.info to 192.168.231.254"}',
# '{"time":"Jan 21 00:01:44","ident":"dnsmasq","owner":"client01","log_format":"dnsmasq","pid":"3468","message":"reply 3x6-.602-.OgEWPzRasaBfzw*1YgPwvfpK5ndYxfeL6t-.AAWCJrJfzqWHDvNtdSStYg3cnHaa0NHOxM-.26JBAO6h3xFvABN5REohh3RObsbew4lIQs-.XDxHdPvCAsmEqutMHFanKav*p1u36CvjZ4-.customers_2017.xlsx.email-19.kennedy-mendoza.info is 195.128.194.168"}',
# '{"time":"Jan 21 00:02:03","ident":"dnsmasq","owner":"client01","log_format":"dnsmasq","pid":"3468","message":"query[A] 3x6-.603-.JAiihufiH6QIEbwkSuO95WxdELeD1lhhZM-.d9flhBVmZjVw*hHY4zQbeBvDhO7Rkx310e-.qpg3bNc2PfFMkhRJ5fHiwXm/77ZJqwhnpT-.wB1zoS/YSaMDXtmgJxN1OFHSuQqg51iWtQ-.customers_2017.xlsx.email-19.kennedy-mendoza.info from 10.143.0.103"}',
# '{"time":"Jan 21 00:02:03","ident":"dnsmasq","owner":"client01","log_format":"dnsmasq","pid":"3468","message":"forwarded 3x6-.603-.JAiihufiH6QIEbwkSuO95WxdELeD1lhhZM-.d9flhBVmZjVw*hHY4zQbeBvDhO7Rkx310e-.qpg3bNc2PfFMkhRJ5fHiwXm/77ZJqwhnpT-.wB1zoS/YSaMDXtmgJxN1OFHSuQqg51iWtQ-.customers_2017.xlsx.email-19.kennedy-mendoza.info to 192.168.231.254"}',
# '{"time":"Jan 21 00:02:03","ident":"dnsmasq","owner":"client01","log_format":"dnsmasq","pid":"3468","message":"reply 3x6-.603-.JAiihufiH6QIEbwkSuO95WxdELeD1lhhZM-.d9flhBVmZjVw*hHY4zQbeBvDhO7Rkx310e-.qpg3bNc2PfFMkhRJ5fHiwXm/77ZJqwhnpT-.wB1zoS/YSaMDXtmgJxN1OFHSuQqg51iWtQ-.customers_2017.xlsx.email-19.kennedy-mendoza.info is 195.128.194.168"}',
# '{"time":"Jan 21 00:02:18","ident":"dnsmasq","owner":"client01","log_format":"dnsmasq","pid":"3468","message":"query[A] 3x6-.604-.MjQIsKRLJeIf3y1wM8tvXuGtFrV3H9WyLp-.FM74lLN5B5lFdxKv/oKEQF1IcKHe4qnp15-.myRWf8hQktgRZYoYMN84ec*T7Tx4Cu0F*5-.Atajwu7v2GXv2WXGRPV6jPKi6tEHcp72sD-.customers_2017.xlsx.email-19.kennedy-mendoza.info from 10.143.0.103"}',
# '{"time":"Jan 21 00:02:18","ident":"dnsmasq","owner":"client01","log_format":"dnsmasq","pid":"3468","message":"forwarded 3x6-.604-.MjQIsKRLJeIf3y1wM8tvXuGtFrV3H9WyLp-.FM74lLN5B5lFdxKv/oKEQF1IcKHe4qnp15-.myRWf8hQktgRZYoYMN84ec*T7Tx4Cu0F*5-.Atajwu7v2GXv2WXGRPV6jPKi6tEHcp72sD-.customers_2017.xlsx.email-19.kennedy-mendoza.info to 192.168.231.254"}',
# '{"time":"Jan 21 00:02:18","ident":"dnsmasq","owner":"client01","log_format":"dnsmasq","pid":"3468","message":"reply 3x6-.604-.MjQIsKRLJeIf3y1wM8tvXuGtFrV3H9WyLp-.FM74lLN5B5lFdxKv/oKEQF1IcKHe4qnp15-.myRWf8hQktgRZYoYMN84ec*T7Tx4Cu0F*5-.Atajwu7v2GXv2WXGRPV6jPKi6tEHcp72sD-.customers_2017.xlsx.email-19.kennedy-mendoza.info is 195.128.194.168"}',
# '{"time":"Jan 21 00:02:27","ident":"dnsmasq","owner":"client01","log_format":"dnsmasq","pid":"3468","message":"query[TXT] current.cvd.clamav.net from 172.19.130.4"}',
# '{"time":"Jan 21 00:02:27","ident":"dnsmasq","owner":"client01","log_format":"dnsmasq","pid":"3468","message":"forwarded current.cvd.clamav.net to 192.168.231.254"}',
# '{"time":"Jan 21 00:02:27","ident":"dnsmasq","owner":"client01","log_format":"dnsmasq","pid":"3468","message":"reply current.cvd.clamav.net is 0.103.5:62:26428:1642717740:1:90:49192:333"}',
# '{"time":"Jan 21 00:02:27","ident":"dnsmasq","owner":"client01","log_format":"dnsmasq","pid":"3468","message":"query[A] db.local.clamav.net from 172.19.130.4"}'
# ]
    

def read_txt_to_list(file_path):
    lines_list = []
    with open(file_path, 'r') as file:
        for line in file:
            lines_list.append(line.strip())  # strip() removes any leading/trailing whitespaces including '\n'
    return lines_list

# Example usage:
# file_path = 's3://siemtest22/siem_spark_model/siem dev2/dnsmasq_sample.txt'  # Replace 'example.txt' with the path to your text file
# file_path2="s3://siemtest22/siem_spark_model/siem dev2/apache_access.txt"
# data = sc.textFile(file_path2)
# data2=sc.textFile(file_path)
data={}
base=500
for i in range(10):
    data[i]=sc.textFile('s3://siemtest22/siem_spark_model/eval_data2/dnsmasq_client2__{num}.json'.format(num=base))
    base=base*2

data_list=[data[x] for x in range(10)]
print("read all test set , prepare for testing")
                        




################################################ uncomment for testing 
# rdd = spark.sparkContext.parallelize(data)
dstream = ssc.queueStream(data_list)

# kinesisStream.pprint()

# Path of Master
loaded_rf_model_dnsmasq = RandomForestClassificationModel.load("s3://siemtest22/siem_spark_model/model/ML_trained_model/rf_model_new")
loaded_rf_model_access= RandomForestClassificationModel.load('s3://siemtest22/siem_spark_model/model/ML_trained_model/rf_model_access')
loaded_rf_model_error=RandomForestClassificationModel.load('s3://siemtest22/siem_spark_model/model/ML_trained_model/rf_model_error')

dstream.foreachRDD(process_rdd)
###################################################################
# Create the Kinesis DStream
# kinesisStream = KinesisUtils.createStream(
#     ssc, kinesisAppName, kinesisStreamName, kinesisEndpointURL, kinesisRegionName,
#     initialPositionInStream=initialPosition, awsAccessKeyId="ACCESS_KEY",awsSecretKey="SECRET_ACCESS_KEY"
#     ,checkpointInterval=10
# )
# parsed_data=kinesisStream.map(lambda x:x)
# parsed_data.foreachRDD(process_rdd)

# Start the computation
ssc.start()
ssc.awaitTermination()



