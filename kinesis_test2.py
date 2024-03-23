from pyspark import SparkContext
from pyspark.streaming import StreamingContext
from pyspark.streaming.kinesis import KinesisUtils, InitialPositionInStream
from pyspark.sql.functions import col,regexp_extract,concat,lit,array,unix_timestamp,when,row_number
from pyspark.sql import Row
from pyspark.sql import SparkSession
import json 
from pyspark.ml.feature import StringIndexer,StringIndexerModel
from pyspark.conf import SparkConf
from rule_base.rules import Apache_error,Dnsmasq

import time

### For Phase 4 ###
from pyspark.sql.functions import from_unixtime, col, unix_timestamp, expr,lag,round,dayofweek,length,regexp_replace,count, desc,udf
from pyspark.sql.window import Window
from pyspark.sql.types import IntegerType,FloatType
import joblib

###############################require configuration for aws 
conf = (
    SparkConf()
    .setAppName("KInesisTest") \
    .set("spark.hadoop.fs.s3a.endpoint", "s3.amazonaws.com") \
    .set("spark.hadoop.fs.s3a.access.key", "ACCESS_KEY") \
    .set("spark.hadoop.fs.s3a.secret.key", "SECRET_ACCESS_KEY") \
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
indexer_dnsmasq = StringIndexerModel.read().load("./model/indexer_dnsmasq")
indexer_error = StringIndexerModel.read().load("./model/indexer_apacheerror")
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

def categorize_ip(value2):
    try:
        # Split IP address into octets
        octets = list(map(int, value2.split('.')))

        # Check if IP is private
        if (octets[0] == 10) or (octets[0] == 172 and 16 <= octets[1] <= 31) or (octets[0] == 192 and octets[1] == 168):
            return 0  # Private IP
        else:
            return 1  # Public IP
    except:
        return 2  # Non-IP values
    
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
    return 1 if any(ext in value.lower() for ext in microsoft_extensions) else 0

def calculate_entropy(value):
    import numpy as np
    counts = {}
    for c in value:
        counts[c] = counts.get(c, 0) + 1
    probabilities = [count / len(value) for count in counts.values()]
    entropy_value = sum(-p * np.log2(p) for p in probabilities)
    return entropy_value
def is_human_readable(entropy_value, threshold=3.0):
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
    df_pyspark = df_pyspark.selectExpr(
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
        'value2_ip_class'
    )
    
    return df_pyspark


def process_rdd(rdd):
    print("enter check")
    start_time_process = time.time()
    if not rdd.isEmpty():
        print("not empty")
        dataframes = {}
        json_rdd = rdd.map(lambda x: json.loads(x))
        # apache_error = json_rdd.filter(lambda x: x.get('log_format') == 'apache_error')
        dnsmasq_rdd = json_rdd.filter(lambda x: x.get('log_format') == 'dnsmasq')
        # apache2_access=json_rdd.filter(lambda x:x.get('log_format')=="apache2_access")

        # if not apache_error.isEmpty():
        #     print("***** phase 1 apache error log seperation ******")
        #     dataframes['apache_error'] = process_apache_error(apache_error)
        #     dataframes['apache_error'].show()
        #     unique_owners=dataframes['apache_error'].select('owner').distinct()
        #     #############LET's seperate by log owner#################################
        #     print("***** phase 2 apache error owner seperation ******")
        #     for row in unique_owners.collect():
                    
        #             # since only 1 column is collected , so it's always at row[0]
        #             unique_value = row[0]
        #             df_temp = dataframes['apache_error'].filter(dataframes['apache_error']['owner'] == unique_value)
        #             df_temp.show()
        #             print("***** phase 3 apache error  rule-base detection ******")
        #             df_checked=Apache_error(df_temp).error_check()
        #             df_checked.show(truncate=False)
        #             # send to anomaly module
        #             print("***** phase 4 apache error  anomaly detection ******")

                    # ######################
                    
            # dataframes['apache_error'].write.mode('overwrite').parquet("C:\\Users\\A570ZD\\Desktop\\kinesis_stream\\temp\\apache_error") 
        if not dnsmasq_rdd.isEmpty():
            print("***** phase 1 dnsmasq log seperation ******")
            
            start_time_dns = time.time()

            dataframes['dnsmasq'] = process_dnsmasq(dnsmasq_rdd)
            # dataframes['dnsmasq'].show()
            unique_owners=dataframes['dnsmasq'].select('owner').distinct()
            unique_owners.show()
            print("Phase 1 - Completed")
            
            end_time_dns = time.time()

            elapsed_time1 = end_time_dns - start_time_dns
            print("log seperation time <dnsmasq_phase_1>:", elapsed_time1, "seconds\n")

            #############LET's seperate by log owner#################################
            
            
            for row in unique_owners.collect():
                    print("***** phase 2 dnsmasq owner seperation & furthur pre-processing ******")
                    start_time_dns = time.time()

                    # since only 1 column is collected , so it's always at row[0]
                    owner = row[0]
                    df_temp = dataframes['dnsmasq'].filter(dataframes['dnsmasq']['owner'] == owner)
                    # owner = df_temp.select("owner").first()[0]
                    # df_temp.show()
                    print("Phase 2 - Completed")
                    df_pyspark = df_temp.alias("df_pyspark")
               
                    df_pyspark = process_dnsmasq_for_pred(df_pyspark) 

                    df_pyspark.show()
                    end_time_dns = time.time()

                    elapsed_time2 = end_time_dns - start_time_dns
                    print(f"Pre-processed time <dnsmasq_phase_2_{owner}>:", elapsed_time2, "seconds\n")
                    
                    print("***** phase 3 dnsmasq  rule-base detection ******")
                    start_time_dns = time.time()

                    ##### code for rule based prediction
                    df_dnsmasq_rule=Dnsmasq(df=df_pyspark,unique_value=owner)
                    if df_dnsmasq_rule.exist:
                        df_check,df_pyspark=df_dnsmasq_rule.error_check()
                        if not df_check.rdd.isEmpty():
                            # df_check.show()
                            df_pyspark.show()
                            print("Phase 3 - Rules activated")
                            
                        else:
                            print("Phase 3 - No Rule Matched")
                    else:
                        # for_anomaly_df=df_pyspark.alias("for_anomaly_df")
                        print("Phase 3 - No Action")

                    # for_anomaly_df = for_anomaly_df.filter(for_anomaly_df['detection'] == "")
                    # for_anomaly_df.show()
                    end_time_dns = time.time()

                    elapsed_time3 = end_time_dns - start_time_dns
                    print(f"Rule-based detetcion time <dnsmasq_phase_3_{owner}>:", elapsed_time3, "seconds\n")

                    # send to anomaly module
                    print("***** phase 4 dnsmasq  anomaly detection ******")
                     
                    start_time_dns = time.time()
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
                    df_pyspark = df_pyspark.withColumn("prediction", predict_data(*list_of_columns))
                    df_pyspark.show()
                    print("Phase 4 - Prediction Ended")

                    end_time_dns = time.time()

                    elapsed_time4 = end_time_dns - start_time_dns
                    print(f"Anomaly detection time <dnsmasq_phase_4_{owner}>:", elapsed_time4, "seconds\n")

                    print("*****phase 5 create rule********")
                    start_time_rule = time.time()

                    # w = Window().orderBy(lit('A'))
                    # prediction_column = prediction_column.withColumn('id', row_number().over(w))
                    # df_pyspark = df_pyspark.withColumn('id', row_number().over(w))
                    # prediction_column.show()
                    # df_pyspark.show()

                    #join together both DataFrames using 'id' column
                    # df_pyspark = df_pyspark.join(prediction_column, on=['id']).drop('id')
                    # df_pyspark.show()
                    df_pyspark=df_pyspark.select('response','value1',"value2","prediction")
                    # df_pyspark.show()
                    df_pyspark=df_pyspark[df_pyspark['prediction']==1].drop('prediction')
                    if not df_pyspark.rdd.isEmpty():
                        try:
                            filtered_df = df_pyspark.filter(df_pyspark["response"].like("%query%")).select("value2").distinct()
                            # filtered_df.show()
                        except Exception as e:
                            # print(e)
                            pass
                        if not filtered_df.rdd.isEmpty():
                            filtered_df.write.csv("./rule_base/{unique_value}/malicious_ip.csv".format(unique_value=owner),mode="append")
                            print('\nPhase 5 - Rule generated ')
                        else:
                            filtered_df.show()
                            print('\nPhase 5 - NO rule generated ')
                    else:
                        df_pyspark.show()
                        print("\nPhase 5 - NO rule generated")

                    end_time_rule = time.time()

                    elapsed_time5 = end_time_rule - start_time_rule
                    print(f"Anomaly detection time <dnsmasq_phase_5_rule>:", elapsed_time5, "seconds\n")

                    ########################
                    print("*********************************** END ***********************************\n")
                    print("Pre-processed time <dnsmasq_phase_1>:", elapsed_time1, "seconds\n")
                    print(f"Pre-processed time <dnsmasq_phase_2_{owner}>:", elapsed_time2, "seconds\n")
                    print(f"Rule-based detetcion time <dnsmasq_phase_3_{owner}>:", elapsed_time3, "seconds\n")
                    print(f"Anomaly detection time <dnsmasq_phase_4_{owner}>:", elapsed_time4, "seconds\n")
                    print(f"Rule creation time <dnsmasq_phase_5_{owner}>:", elapsed_time5, "seconds\n")
       

                    
           
            # dataframes['dnsmasq'].write.mode('overwrite').parquet("C:\\Users\\A570ZD\\Desktop\\kinesis_stream\\temp\\dnsmasq") 
        # if not apache2_access.isEmpty():
        #     print("***** phase 1 apache2 access log seperation ******")
        #     dataframes['apache2_access']=process_apache2_access(apache2_access)
        #     dataframes['apache2_access'].show()
        #     unique_owners=dataframes['apache2_access'].select('owner').distinct()
        #     #############LET's seperate by log owner#################################
        #     print("***** phase 2 apache2 access owner seperation ******")
        #     for row in unique_owners.collect():
                    
        #             # since only 1 column is collected , so it's always at row[0]
        #             unique_value = row[0]
        #             df_temp = dataframes['apache2_access'].filter(dataframes['apache2_access']['owner'] == unique_value)
        #             df_temp.show()
        #             print("***** phase 3 apache error  rule-base detection ******")
        #             # send to anomaly module
        #             print("***** phase 4 apache error  anomaly detection ******")
        #             ##################
        
            # dataframes['apache2_access'].write.mode('overwrite').parquet("C:\\Users\\A570ZD\\Desktop\\kinesis_stream\\temp\\apache2_access") 
                    
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
file_path = 'dnsmasq_sample_chop.txt'  # Replace 'example.txt' with the path to your text file
data = read_txt_to_list(file_path)



################################################ uncomment for testing 
rdd = spark.sparkContext.parallelize(data)
dstream = ssc.queueStream([rdd])

# kinesisStream.pprint()

# Path of Master
log_model = joblib.load('C:\\Users\\A570ZD\\Desktop\\siem dev2\\model\\ML_trained_model\\RandomForestClassifier30.joblib')
# log_model = joblib.load('C:\\Users\\Prompt\\Desktop\\mas2\\siem\\model\\ML_trained_model\\RandomForestClassifier30.joblib')

log_model.feature_names = None

broadcast_model = sc.broadcast(log_model)
@udf('integer')
def predict_data(*cols):
    return int(broadcast_model.value.predict((cols,)))

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



