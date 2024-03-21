# from pyspark import SparkContext
# from pyspark.streaming import StreamingContext
# from pyspark.streaming.kinesis import KinesisUtils, InitialPositionInStream
from pyspark.sql.functions import col,regexp_extract,when,concat_ws,count
# from pyspark.sql import Row
# from pyspark.sql import SparkSession
# import json 
# from pyspark.ml.feature import StringIndexer,StringIndexerModel
# from pyspark.conf import SparkConf
# import rule_base.rules as rb
import xml.etree.ElementTree as ET

class Apache_error:
 
    # init method or constructor
    def __init__(self, df):
        tree = ET.parse('C:\\Users\\A570ZD\\Desktop\\siem dev\\xml_parser\\0250-apache_rules.xml')
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
    def __init__(self,unique_value,df,):

        setrule_df = spark.read.csv(path.format(unique_value=unique_value))
        setrule_list = setrule_df.rdd.flatMap(lambda x: x).collect()

        self.df = df
        self.rule_file={}

        for item in filtered_list:
            rule_list.update({"Malicious IP: "+item:(col("entity")==item)})
    
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

        
 