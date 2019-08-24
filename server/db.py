from pymongo import MongoClient

DB_NAME = "abcxyz"  
DB_HOST = "dsxxxxxx.mlab.com"
DB_PORT = "xxxxx"
DB_USER = "username" 
DB_PASS = "password"

connection = MongoClient(DB_HOST, DB_PORT, retryWrites=False)
db = connection[DB_NAME]
db.authenticate(DB_USER, DB_PASS)
