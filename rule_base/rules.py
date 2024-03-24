# from pyspark import SparkContext
# from pyspark.streaming import StreamingContext
# from pyspark.streaming.kinesis import KinesisUtils, InitialPositionInStream
from pyspark.sql.functions import col,regexp_extract,when,concat_ws,count,row_number
from pyspark.sql import Window
# from pyspark.sql import Row
from pyspark.sql import SparkSession
# import json 
# from pyspark.ml.feature import StringIndexer,StringIndexerModel
# from pyspark.conf import SparkConf
# import rule_base.rules as rb
import xml.etree.ElementTree as ET
from os import path


class Apache_error:
 
    # init method or constructor
    def __init__(self, df):
        tree = ET.parse('s3://siemtest22/siem_spark_model/siem dev2/xml_parser/0250-apache_rules.xml')
        root = tree.getroot()

        self.df = df
        self.rule_file={
        # "Forbidden Directory Access_denied": (col("entity")=="AH01276"),
        # "Forbidden  Directory Access_denied by rules":(col("entity")=="AH01630")
        }

        for i in range(len(root)):
            for j in range(len(root[i])):
                if root[i][j].tag == 'id':
                    error_id = root[i][j].text.split('|')
                    for entity in error_id:
                        self.rule_file.update({root[i][j+1].text:(col("entity")==entity)})


    def error_check(self):
        entity_regex=r'(\S+):'
        ip_regex=r'(\d+.\d+.\d+.\d+):?(\d+)?'
        df = self.df.withColumn("entity", regexp_extract("entity", entity_regex, 1))
        detections = []
        for rule, condition in self.rule_file.items():
            detections.append(when(condition, rule))
        df = df.withColumn("detection", concat_ws(",", *detections))
        df=df.withColumn("srcip",regexp_extract('client',ip_regex,1)) \
        .withColumn("srcport",regexp_extract('client',ip_regex,2))
        result_df = df[df['detection'] != ""].select(['srcip', 'detection']).groupBy('srcip', 'detection').agg(count('*').alias('count')).distinct()
        return result_df

class Dnsmasq:
    # init method or constructor
    def __init__(self,unique_value,df):
        spark=SparkSession.builder.getOrCreate()
        client_path="s3://siemtest22/siem_spark_model/siem dev2/rule_base/{unique_value}/malicious_ip.parquet".format(unique_value=unique_value)
        try:
            df_check = spark.read.text(client_path)
            exist=True
        except:
            exist=False
        self.exist=exist
        if self.exist:
            setrule_df = spark.read.parquet(client_path)
            setrule_list = setrule_df.rdd.flatMap(lambda x: x).collect()
            self.df = df
            self.rule_file={}
            for item in setrule_list:
                self.rule_file.update({"Malicious IP Founded in DNSMASQ: "+item:(col("value2")==item)})


    
    def error_check(self):
        # entity_regex=r'(\S+):'
        # ip_regex=r'(\d+.\d+.\d+.\d+):?(\d+)?'
        # df = self.df.withColumn("entity", regexp_extract("entity", entity_regex, 1))
        df=self.df
        detections = []
        for rule, condition in self.rule_file.items():
            detections.append(when(condition, rule))

        df = df.withColumn("detection", concat_ws(",", *detections))
        df=df.withColumn("get_malicious_domain", when(col("detection") != "", col("value1")).otherwise(None))
        distinct_values = df.select('get_malicious_domain').distinct().rdd.flatMap(lambda x: x).collect()
        # print(distinct_values)
        df = df.withColumn('temp_for_check_association', when(col('value1').isin(distinct_values), col('value1')))
        # df=df.withColumn("associate_with_malicious_IP_query", when(col("value1") != "", col("value1")))
        # df.show()
        window_spec = Window.partitionBy("value1").orderBy("value1")
        df_for_anomaly = df.withColumn("row_num", row_number().over(window_spec))
        # df_for_anomaly.show()
        df_for_anomaly_filtered = df_for_anomaly.filter(~((df_for_anomaly["row_num"] > 3) & (df_for_anomaly["temp_for_check_association"] != None)))
        df_for_anomaly_filtered = df_for_anomaly_filtered.filter((df_for_anomaly["temp_for_check_association"].isNull()))
        df_for_anomaly_filtered = df_for_anomaly_filtered.drop("row_num","temp_for_check_association","get_malicious_domain")
        df_for_anomaly_filtered = df_for_anomaly_filtered.filter((df_for_anomaly["detection"] == ""))
        # df=df.withColumn("srcip",regexp_extract('client',ip_regex,1)) \
        # .withColumn("srcport",regexp_extract('client',ip_regex,2))
        result_df = df[df['detection'] != ""].select(['value2', 'detection']).groupBy('value2', 'detection').agg(count('*').alias('count')).distinct()
        return result_df,df_for_anomaly_filtered

        
 