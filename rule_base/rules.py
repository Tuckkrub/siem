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

class Apache_error:
 
    # init method or constructor
    def __init__(self, df):
        self.df = df
        self.rule_file={
        "Forbidden Directory Access_denied": (col("entity")=="AH01276"),
        "Forbidden  Directory Access_denied by rules":(col("entity")=="AH01630")
    } 
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
 