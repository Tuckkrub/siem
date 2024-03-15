from pyspark import SparkContext
from pyspark.streaming import StreamingContext
from pyspark.streaming.kinesis import KinesisUtils, InitialPositionInStream
from pyspark.sql.functions import col,regexp_extract,concat,lit,array,unix_timestamp,when
from pyspark.sql import Row
from pyspark.sql import SparkSession
import json 
from pyspark.ml.feature import StringIndexer,StringIndexerModel
from pyspark.conf import SparkConf
from rule_base.rules import Apache_error

### For Phase 4 ###
from pyspark.sql.functions import from_unixtime, col, unix_timestamp, expr,lag,round,dayofweek,length,regexp_replace,count, desc,udf
from pyspark.sql.window import Window
from pyspark.sql.types import IntegerType
import joblib

### pip install --upgrade scikit-learn==1.4.1.post1

### For Phase 4 ###



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
indexer_dnsmasq = StringIndexerModel.read().load("C:/Users/Prompt/Desktop/siemmm/siem/model/indexer_dnsmasq")
indexer_error = StringIndexerModel.read().load("C:/Users/Prompt/Desktop/siemmm/siem/model/indexer_apacheerror")
################################################################################

################regex for building key-value ######################################################################
dnsmasq_regex = r"([a-z]+\[?[A-Z]*\]?)\s(\S+)\s([fromtois]+)\s(\S+)"
error_regex_final_maybe=r"([^:']+:?)(('[^']+')?(\snot found or unable to stat))?(\s*([^\/:,'\(]+:?[^:\/,'\(]+:?)\s*(.*?(?=, referer|$)))?((, referer:)(.*))?"
###########################################################################################################

def process_dnsmasq(filtered_rdd):
    #fix timestamp, create key, create value    # .withColumn("value", array("domain", "ip_addr")) \
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
    df_indexed=df_indexed.drop("pid","time","response","domain","term","ip_addr")
    return df_indexed

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

def process_dnsmasq_for_pred(df_pyspark):
    df_pyspark = df_pyspark.drop("ident", "log_format", "owner", "message")  # Remove unnecessary columns
    df_pyspark = df_pyspark.withColumn("encoded_key", col("encoded_key").cast("int"))
    df_pyspark = df_pyspark.withColumn("timestamp_datetime", from_unixtime("epoch_timestamp").cast("timestamp"))

    lag_col = lag(col("epoch_timestamp")).over(Window.orderBy("epoch_timestamp"))
    df_pyspark = df_pyspark.withColumn("time_diff_unix", round((col("epoch_timestamp") - lag_col), 1))
    df_pyspark = df_pyspark.fillna(0, subset=["time_diff_unix"])
    df_pyspark = df_pyspark.withColumn("time_diff_unix", col("time_diff_unix").cast("decimal(10,1)"))

    df_pyspark = df_pyspark.withColumn("day_of_week", dayofweek("timestamp_datetime"))
    
    df_pyspark = df_pyspark.withColumn("value1_length", length("value1"))
    df_pyspark = df_pyspark.withColumn("value2_length", length("value2"))

    df_pyspark = df_pyspark.withColumn("value1_dot_count", (length("value1") - length(regexp_replace("value1", "[^.]", ""))))
    df_pyspark = df_pyspark.withColumn("value1_hyphen_count", (length("value1") - length(regexp_replace("value1", "[^-]", ""))))
    
    df_pyspark = df_pyspark.withColumn("value2_dot_count", (length("value2") - length(regexp_replace("value2", "[^.]", ""))))
    df_pyspark = df_pyspark.withColumn("value2_hyphen_count", (length("value2") - length(regexp_replace("value2", "[^-]", ""))))

    df_pyspark = df_pyspark.withColumn("key_length", length("key"))

    window_spec_value1 = Window().orderBy("value1")
    window_spec_value2 = Window().orderBy("value2")
    
    df_pyspark = df_pyspark.withColumn("value1_count", count("value1").over(window_spec_value1))
    df_pyspark = df_pyspark.withColumn("value2_count", count("value2").over(window_spec_value2))

    # Register the UDF
    categorize_ip_udf = udf(categorize_ip, IntegerType())
    
    # Apply the UDF to create a new column 'ip_category'
    df_pyspark = df_pyspark.withColumn("value2_ip_class", categorize_ip_udf("value2"))

    df_pyspark = df_pyspark.drop("key", "value1", "value2", "epoch_timestamp","timestamp_datetime")
    df_pyspark = df_pyspark.selectExpr(
        'encoded_key',
        'time_diff_unix',
        'day_of_week',
        'value1_length',
        'value2_length',
        'value1_dot_count',
        'value1_hyphen_count',
        'value2_dot_count',
        'value2_hyphen_count',
        'key_length',
        'value1_count',
        'value2_count',
        'value2_ip_class'  # Assuming this column needs to be added
    )
    
    return df_pyspark



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

def process_rdd(rdd):
    print("enter check")
    if not rdd.isEmpty():
        print("not empty")
        dataframes = {}
        json_rdd = rdd.map(lambda x: json.loads(x))
        apache_error = json_rdd.filter(lambda x: x.get('log_format') == 'apache_error')
        dnsmasq_rdd = json_rdd.filter(lambda x: x.get('log_format') == 'dnsmasq')
        apache2_access=json_rdd.filter(lambda x:x.get('log_format')=="apache2_access")

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
            dataframes['dnsmasq'] = process_dnsmasq(dnsmasq_rdd)
            dataframes['dnsmasq'].show()
            unique_owners=dataframes['dnsmasq'].select('owner').distinct()
            #############LET's seperate by log owner#################################
            print("***** phase 2 dnsmasq owner seperation ******")
            
            # log_model = joblib.load('C:/Users/Prompt/Desktop/siemmm/siem/ML_trained_model/RandomForestClassifier_window.joblib')
            log_model = joblib.load('C:/Users/Prompt/Desktop/siemmm/siem/ML_trained_model/RandomForestClassifier2.joblib')
            log_model.feature_names = None


            broadcast_model = sc.broadcast(log_model)
            @udf('integer')
            def predict_data(*cols):
                return int(broadcast_model.value.predict((cols,)))

            for row in unique_owners.collect():
                    
                    # since only 1 column is collected , so it's always at row[0]
                    unique_value = row[0]
                    df_temp = dataframes['dnsmasq'].filter(dataframes['dnsmasq']['owner'] == unique_value)
                    df_temp.show()
                    
                    # csv_output_path = f"df_temp{row}.csv"
                    # df_temp.coalesce(1).write.csv(csv_output_path, header=True, mode="overwrite")

                    print("***** phase 3 apache error  rule-base detection ******")
                    # send to anomaly module
                    print("***** phase 4 apache error  anomaly detection ******")
                    df_temp = process_dnsmasq_for_pred(df_temp)        
                    df_temp.show()

                    list_of_columns = df_temp.columns
                    df_temp = df_temp.withColumn("prediction", predict_data(*list_of_columns))
                    df_temp.show()

                    ########################
                    print("************ END ***********************************")
                    
           
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



# TEST DATA
data=[
'{"time":"Jan 18 10:07:23.284717 2022","log_format":"apache_error","owner":"client01","level":"php7:warn","pid":"27406","client":"10.35.35.206:32894","message":"PHP Warning:  scandir(/var/www/intranet.price.fox.org/wp-content/uploads/wpdiscuz/cache/gravatars/): failed to open dir: No such file or directory in /var/www/intranet.price.fox.org/wp-content/plugins/wpdiscuz/utils/class.WpdiscuzCache.php on line 190"}',
'{"time":"Jan 18 10:07:23.284843 2022","log_format":"apache_error","owner":"client01","level":"php7:warn","pid":"27406","client":"10.35.35.206:32894","message":"PHP Warning:  scandir(): (errno 2): No such file or directory in /var/www/intranet.price.fox.org/wp-content/plugins/wpdiscuz/utils/class.WpdiscuzCache.php on line 190"}',
'{"time":"Jan 18 12:17:52.008720 2022","log_format":"apache_error","owner":"client01","level":"php7:error","pid":"28411","client":"172.17.130.196:55206","message":"script \'/var/www/intranet.price.fox.org/searchreplacedb2.php\' not found or unable to stat, referer: https://intranet.price.fox.org"}',
'{"time":"Jan 18 12:17:52.452415 2022","log_format":"apache_error","owner":"client01","level":"autoindex:error","pid":"28490","client":"172.17.130.196:55208","message":"AH01276: Cannot serve directory /var/www/intranet.price.fox.org/wp-content/uploads/: No matching DirectoryIndex (index.html,index.cgi,index.pl,index.php,index.xhtml,index.htm) found, and server-generated directory index forbidden by Options directive, referer: https://intranet.price.fox.org"}',
'{"time":"Jan 18 12:17:52.466276 2022","log_format":"apache_error","owner":"client01","level":"php7:error","pid":"28490","client":"172.17.130.196:55208","message":"script \'/var/www/intranet.price.fox.org/emergency.php\' not found or unable to stat, referer: https://intranet.price.fox.org"}',
'{"host":"172.17.130.196","owner":"client01","log_format":"apache2_access","user":"-","method":"GET","path":"/","code":"200","size":"6128","referer":"-","agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/95.0.4638.69 Safari/537.36"}',
'{"host":"172.17.130.196","owner":"client01","log_format":"apache2_access","user":"-","method":"GET","path":"/wp-includes/css/dist/block-library/style.min.css?ver=5.8.3","code":"200","size":"10846","referer":"http://intranet.price.fox.org/","agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/95.0.4638.69 Safari/537.36"}',
'{"host":"172.17.130.196","owner":"client01","log_format":"apache2_access","user":"-","method":"GET","path":"/wp-content/themes/go/dist/css/design-styles/style-traditional.min.css?ver=1.5.1","code":"200","size":"1489","referer":"http://intranet.price.fox.org/","agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/95.0.4638.69 Safari/537.36"}',
'{"host":"172.17.130.196","owner":"client01","log_format":"apache2_access","user":"-","method":"GET","path":"/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.3.2","code":"200","size":"4505","referer":"http://intranet.price.fox.org/","agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/95.0.4638.69 Safari/537.36"}',
'{"time":"Jan 15 00:50:49","owner":"client01","log_format":"dnsmasq","ident":"dnsmasq","pid":"14522","message":"forwarded 3x6-.56-.puyHMO65WQay9W50yFuPHzuA0gKxMHT9YpNIt5hMsnVYHTMJa*Gn5RwujF/N-.Wh4YPx4FFIAGRk1A/iDOg8bNd9EVRM2Gn0E4o3GtC7cxZqn0xupfxhyW2cqm-.dFr/sQ7M4FyQ8btKYS/PgpaTHQhHmECqSBh63websgGDqT2YgU6dorqo/WW9-.customers_2020.xlsx.ycgjslfptkev.com to 192.168.255.254"}',
'{"time":"Jan 15 00:50:49","owner":"client02","log_format":"dnsmasq","ident":"dnsmasq","pid":"14522","message":"reply 3x6-.56-.puyHMO65WQay9W50yFuPHzuA0gKxMHT9YpNIt5hMsnVYHTMJa*Gn5RwujF/N-.Wh4YPx4FFIAGRk1A/iDOg8bNd9EVRM2Gn0E4o3GtC7cxZqn0xupfxhyW2cqm-.dFr/sQ7M4FyQ8btKYS/PgpaTHQhHmECqSBh63websgGDqT2YgU6dorqo/WW9-.customers_2020.xlsx.ycgjslfptkev.com is 195.128.194.168"}',
'{"time":"Jan 15 00:51:08","owner":"client02","log_format":"dnsmasq","ident":"dnsmasq","pid":"14522","message":"query[A] 3x6-.57-.aSXmHVvNtPlI6nn7sMgzIBxUqwKaz4Fw34iaUUB91wYosNXhQw/3hqP3lEhJ-.FdC1BOmcTp10hjUtERubfqSWkqWmbX03zRTNciAh*pn4kHmf8NjdkJW19Vzg-.G08nsV1ABGmhIYjhSU7SLGxnitbSiX0R*UBA563v93Pd3OpTRiU/PPUpKCiI-.customers_2020.xlsx.ycgjslfptkev.com from 10.35.33.111"}',
'{"time":"Jan 15 00:51:08","owner":"client01","log_format":"dnsmasq","ident":"dnsmasq","pid":"14522","message":"forwarded 3x6-.57-.aSXmHVvNtPlI6nn7sMgzIBxUqwKaz4Fw34iaUUB91wYosNXhQw/3hqP3lEhJ-.FdC1BOmcTp10hjUtERubfqSWkqWmbX03zRTNciAh*pn4kHmf8NjdkJW19Vzg-.G08nsV1ABGmhIYjhSU7SLGxnitbSiX0R*UBA563v93Pd3OpTRiU/PPUpKCiI-.customers_2020.xlsx.ycgjslfptkev.com to 192.168.255.254"}',
'{"time":"Jan 15 00:51:08","owner":"client01","log_format":"dnsmasq","ident":"dnsmasq","pid":"14522","message":"reply 3x6-.57-.aSXmHVvNtPlI6nn7sMgzIBxUqwKaz4Fw34iaUUB91wYosNXhQw/3hqP3lEhJ-.FdC1BOmcTp10hjUtERubfqSWkqWmbX03zRTNciAh*pn4kHmf8NjdkJW19Vzg-.G08nsV1ABGmhIYjhSU7SLGxnitbSiX0R*UBA563v93Pd3OpTRiU/PPUpKCiI-.customers_2020.xlsx.ycgjslfptkev.com is 195.128.194.168"}',
'{"time":"Jan 15 00:51:09","owner":"client01","log_format":"dnsmasq","ident":"dnsmasq","pid":"14522","message":"query[A] motd.ubuntu.com from 10.35.35.118"}',
'{"time":"Jan 15 00:50:49","owner":"client01","log_format":"dnsmasq","ident":"dnsmasq","pid":"14522","message":"forwarded 3x6-.56-.puyHMO65WQay9W50yFuPHzuA0gKxMHT9YpNIt5hMsnVYHTMJa*Gn5RwujF/N-.Wh4YPx4FFIAGRk1A/iDOg8bNd9EVRM2Gn0E4o3GtC7cxZqn0xupfxhyW2cqm-.dFr/sQ7M4FyQ8btKYS/PgpaTHQhHmECqSBh63websgGDqT2YgU6dorqo/WW9-.customers_2020.xlsx.ycgjslfptkev.com to 192.168.255.254"}',
'{"time":"Jan 15 00:50:49","owner":"client02","log_format":"dnsmasq","ident":"dnsmasq","pid":"14522","message":"reply 3x6-.56-.puyHMO65WQay9W50yFuPHzuA0gKxMHT9YpNIt5hMsnVYHTMJa*Gn5RwujF/N-.Wh4YPx4FFIAGRk1A/iDOg8bNd9EVRM2Gn0E4o3GtC7cxZqn0xupfxhyW2cqm-.dFr/sQ7M4FyQ8btKYS/PgpaTHQhHmECqSBh63websgGDqT2YgU6dorqo/WW9-.customers_2020.xlsx.ycgjslfptkev.com is 195.128.194.168"}',
'{"time":"Jan 15 00:51:08","owner":"client02","log_format":"dnsmasq","ident":"dnsmasq","pid":"14522","message":"query[A] 3x6-.57-.aSXmHVvNtPlI6nn7sMgzIBxUqwKaz4Fw34iaUUB91wYosNXhQw/3hqP3lEhJ-.FdC1BOmcTp10hjUtERubfqSWkqWmbX03zRTNciAh*pn4kHmf8NjdkJW19Vzg-.G08nsV1ABGmhIYjhSU7SLGxnitbSiX0R*UBA563v93Pd3OpTRiU/PPUpKCiI-.customers_2020.xlsx.ycgjslfptkev.com from 10.35.33.111"}',
'{"time":"Jan 15 00:51:08","owner":"client01","log_format":"dnsmasq","ident":"dnsmasq","pid":"14522","message":"forwarded 3x6-.57-.aSXmHVvNtPlI6nn7sMgzIBxUqwKaz4Fw34iaUUB91wYosNXhQw/3hqP3lEhJ-.FdC1BOmcTp10hjUtERubfqSWkqWmbX03zRTNciAh*pn4kHmf8NjdkJW19Vzg-.G08nsV1ABGmhIYjhSU7SLGxnitbSiX0R*UBA563v93Pd3OpTRiU/PPUpKCiI-.customers_2020.xlsx.ycgjslfptkev.com to 192.168.255.254"}',
'{"time":"Jan 15 00:51:08","owner":"client01","log_format":"dnsmasq","ident":"dnsmasq","pid":"14522","message":"reply 3x6-.57-.aSXmHVvNtPlI6nn7sMgzIBxUqwKaz4Fw34iaUUB91wYosNXhQw/3hqP3lEhJ-.FdC1BOmcTp10hjUtERubfqSWkqWmbX03zRTNciAh*pn4kHmf8NjdkJW19Vzg-.G08nsV1ABGmhIYjhSU7SLGxnitbSiX0R*UBA563v93Pd3OpTRiU/PPUpKCiI-.customers_2020.xlsx.ycgjslfptkev.com is 195.128.194.168"}',
'{"time":"Jan 15 00:51:09","owner":"client01","log_format":"dnsmasq","ident":"dnsmasq","pid":"14522","message":"query[A] motd.ubuntu.com from 10.35.35.118"}'
]


################################################ uncomment for testing 
rdd = spark.sparkContext.parallelize(data)
dstream = ssc.queueStream([rdd])

# kinesisStream.pprint()
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



