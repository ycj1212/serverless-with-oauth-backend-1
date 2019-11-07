from elasticsearch import Elasticsearch
import pprint as ppr
import json
import random
from datetime import datetime,timedelta
import jwt

class ElaAPI:
    es = Elasticsearch(hosts="13.124.191.146", port=9200)   # 객체 생성
    def allIndex(cls):
        # Elasticsearch에 있는 모든 Index 조회
        print (cls.es.cat.indices())

#재헌이꺼 시작
    def grants_dataInsert(cls,username):
        #datetime init
        now = datetime.now()
        current = str(now.isoformat())
        next_current = str(now+timedelta(seconds=5))
        # 아이디 jwt 인코딩
        encodedId = jwt.encode(
            {
                'userId': username,
                'created': current
            },
            ''+username+current,
            algorithm = 'HS256'
        )
        encodedId = str(encodedId)
        grants_data = {
            "id" : encodedId,
            "created" : current,
            "expired" : next_current
        }
        res = cls.es.search(
            index = "grants",
            body = {
                "query": {
                    "match" : {
                        "_id" : username
                    }
                }
            })
        boolean_value = res["hits"]["total"]["value"]
        if boolean_value == 0:
            res = cls.es.index(index="grants",doc_type="_doc",id=username,body=grants_data)
            print(res)
            return {
                'statusCode': 200,
                'body': {
                    'grants': encodedId
                }
            }
        else:
            print("Grants: user already exist")
            return {
                'statusCode': 200,
                'body': {
                    'grants': encodedId
                }
            }
    
    def grants_search(cls, indx=None):
        res = cls.es.search(
            index = "grants",
            body = {
                "query":{"match_all":{}}
            }
        )
        data = json.dumps(res, ensure_ascii=False, indent=4)
        data = json.loads(data)
        for i in range(len(data["hits"]["hits"])):
            print(data["hits"]["hits"][i]["_id"])
            print(data["hits"]["hits"][i]["_source"]["id"])
            print(data["hits"]["hits"][i]["_source"]["created"])
            print(data["hits"]["hits"][i]["_source"]["expired"])
    def grants_delete(cls,username):
        res = cls.es.delete(index="grants",doc_type="_doc",id=username)
        print(res)
    
#재헌이꺼 끝
##철주꺼 시작
    def tokens_dataInsert(cls,username):
        now = datetime.now()
        current = str(now.isoformat())
        next_current = str(now+timedelta(hours=1))
        tokens_data = {
            "accessToken" : "value of accessToken",
            "refreshToken" : "value of refreshToken",
            "expired_accessToken" : current,
            "expired_refreshToken" : next_current
            }
        res = cls.es.search(
            index = "tokens",
            body = {
                "query": {
                    "match" : {
                        "_id" : username
                    }
                }
            })
        boolean_value = res["hits"]["total"]["value"]
        if boolean_value == 0:
            res = cls.es.index(index="tokens",doc_type="_doc",id=username,body=tokens_data)
            print(res)
        else:
            print("user already exist")


    def tokens_search(cls, indx=None):
    # ===============
    # 데이터 조회 [전체]
    # ===============
        res = cls.es.search(
        index = "tokens",
        body = {
            "query":{"match_all":{}}
            }
        )
        data = json.dumps(res, ensure_ascii=False, indent=4)
        data = json.loads(data)
        for i in range(len(data["hits"]["hits"])):
            print(data["hits"]["hits"][i]["_id"])
            print(data["hits"]["hits"][i]["_source"]["accessToken"])
            print(data["hits"]["hits"][i]["_source"]["refreshToken"])
            print(data["hits"]["hits"][i]["_source"]["expired_accessToken"])
            print(data["hits"]["hits"][i]["_source"]["expired_refreshToken"])
    def tokens_delete(cls,username):
        res = cls.es.search(
                index = "users",
                body = {
                    "query": {
                        "match" : {
                            "_id" : username
                        }
                    }
                })
        boolean_value = res["hits"]["total"]["value"]
        if boolean_value == 1:
            res = cls.es.delete(index="tokens",doc_type="_doc",id=username)
            print("success delete for tokens")
        else:
            print("not exist username for tokens")
#철쭈꺼 끝
#한설꺼 시작
    def users_search(cls, index=None):
    # ===============
    # 데이터 조회 [전체]
    # ===============
        res = cls.es.search(
        index = "users",
        body = {
            "query":{"match_all":{}}
            }
        )
        data = json.dumps(res, ensure_ascii=False, indent=4)
        data = json.loads(data)
        for i in range(len(data["hits"]["hits"])):
            print(data["hits"]["hits"][i]["_id"])
            print(data["hits"]["hits"][i]["_source"]["password"])

    def users_dataInsert(cls,username,password):
        users_data = {
            "password" : password,
            }
        res = cls.es.search(
            index = "users",
            body = {
                "query": {
                    "match" : {
                        "_id" : username
                    }
                }
            })
        boolean_value = res["hits"]["total"]["value"]
        if boolean_value == 0:
            res = cls.es.index(index="users",doc_type="_doc",id=username,body=users_data)
            print(res)
        else:
            print("user already exist")
            
    def users_delete(cls,username):
        res = cls.es.search(
                index = "users",
                body = {
                    "query": {
                        "match" : {
                            "_id" : username
                        }
                    }
                })
        boolean_value = res["hits"]["total"]["value"]
        if boolean_value == 1:
            res = cls.es.delete(index="users",doc_type="_doc",id=username)
            print("success delete for users")
        else:
            print("not exist username for users")

    def login(cls,username,passwd):
        # 아이디 존재 여부 탐색
        res = cls.es.search(
                index = "users",
                body = {
                    "query": {
                        "match" : {
                            "_id" : username
                        }
                    }
                })
        boolean_value = res["hits"]["total"]["value"]
        # 아이디 O
        if boolean_value == 1:
            ps = res["hits"]["hits"][0]["_source"]["password"]
            # 비밀번호 O
            if passwd == ps:
                print("Login: verified")
                grantsId = cls.grants_dataInsert(username)
                return grantsId
            # 비밀번호 X
            else:
                print("Login: failed")
                return {
                    'statusCode': 401,
                    'body': 'Incorrect password'
                }
        # 아이디 X
        else:
            print("Login: not exist user")
            return {
                'statusCode': 401,
                'body': 'There is no userId'
            }
        
#한설꺼 끝
    def deleteIndex(cls,index_name):
        cls.es.indices.delete(index=index_name)

es = ElaAPI()

#es.users_dataInsert("hanseol","123456")
#es.users_search()
#es.users_delete("ko")
#es.login("hanseol","1212412456")

#es.grants_dataInsert("senkl")
#es.grants_search()
#es.grants_delete('kohanseol')

#es.tokens_dataInsert("yang")
#es.tokens_search()
#es.tokens_delete("yggg")

def handler(event):
    # 보안 인증서 발급
    grant = es.login(event['userId'], event['password'])

if __name__ == "__main__":
    handler({'userId': 'hanseol', 'password': '123456'})