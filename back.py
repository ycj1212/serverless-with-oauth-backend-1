from elasticsearch import Elasticsearch
import pprint as ppr
import json
import random
from datetime import datetime,timedelta
import jwt
import time
import dateutil.parser import parse

class ElaAPI:
    es = Elasticsearch(hosts="15.164.95.53", port=9200)   # 객체 생성
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
        print(type(encodedId))
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
            for i in range(len(res["hits"]["hits"])):
                if res["hits"]["hits"][i]["_id"] == username:
                    return {
                        'statusCode': 200,
                        'body': {
                            'grants': res['hits']['hits'][i]['_source']['id']
                        }
                    }
                    
    def grants_search(cls, index=None):
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
        expired_accessToken = str(now+timedelta(hours=1))
        expired_refreshToken = str(now+timedelta(hours=12))
        accessToken = jwt.encode(
            {
                'userId': username,
                'expired_accessToken': expired_accessToken
            },
            ''+username,
            algorithm = 'HS256'
        ).decode('utf-8')
        refreshToken = jwt.encode(
            {
                'userId': username,
                'expired_refreshToken': expired_refreshToken
            },
            ''+username,
            algorithm = 'HS256'
        ).decode('utf-8')
        accessToken = str(accessToken)
        refreshToken = str(refreshToken)
        tokens_data = {
            "accessToken" : accessToken,
            "refreshToken" : refreshToken,
            "expired_accessToken" : expired_accessToken,
            "expired_refreshToken" : expired_refreshToken
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
            return {
                'statusCode': 200,
                'body': {
                    'accessToken': accessToken,
                    'refreshToken': refreshToken
                }
            }
        else:
            print("Tokens: user already exist")
            for i in range(len(res["hits"]["hits"])):
                if res["hits"]["hits"][i]["_id"] == username:
                    return {
                        'statusCode': 200,
                        'body': {
                            'accessToken': res["hits"]["hits"][i]["_source"]["accessToken"],
                            'refreshToken': res["hits"]["hits"][i]["_source"]["refreshToken"]
                        }
                    }


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


    def checkGrants(cls,grant):
        res = cls.es.search(
            index = "grants",
            body = {
                "query":{"match_all":{}}
            }
        )
        data = json.dumps(res, ensure_ascii=False, indent=4)
        data = json.loads(data)
        comp = False
        for i in range(len(data["hits"]["hits"])):
            if data["hits"]["hits"][i]["_source"]["id"] == grant:
                comp = True
                break

        if comp == True:
            return {
                'statusCode': 200,
                'body': {
                    'userId': data["hits"]["hits"][i]["_id"],
                    'created': data["hits"]["hits"][i]['_source']['created']
                }
            }
        else:
            return {
                'statusCode': 401,
                'body': 'There is no userId'
            }

    def checkTokens(cls,token):
        res = cls.es.search(
            index = "tokens",
            body = {
                "query":{"match_all":{}}
            }
        )
        data = json.dumps(res, ensure_ascii=False, indent=4)
        data = json.loads(data)
        for i in range(len(data["hits"]["hits"])):
            if data["hits"]["hits"][i]["_source"]["accessToken"] == token:
                comp = True
                break
            else:
                comp = False
        
        if comp == True:
            return {
                'statusCode': 200
                'body': {
                    'userId': data["hits"]["hits"][i]["_id"],
                    'expired_accessToken': data["hits"]["hits"][i]["_source"]["expired_accessToken"]
                }
            }
        else:
            return {
                'statusCode': 401,
                'body': 'There is no grantsId'
            }
            
    def checkReTokens(cls,refreshToken):
        res = cls.es.search(
            index = "tokens",
            body = {
                "query":{"match_all":{}}
            }
        )
        data = json.dumps(res, ensure_ascii=False, indent=4)
        data = json.loads(data)
        for i in range(len(data["hits"]["hits"])):
            if data["hits"]["hits"][i]["_source"]["refreshToken"] == refreshToken:
                comp = True
                break
            else:
                comp = False
        
        if comp == True:
            return {
                'statusCode': 200,
                'body': {
                    'userId': data["hits"]["hits"][i]["_id"],
                    'expired_refreshToken': data["hits"]["hits"][i]["_source"]["expired_refreshToken"]
                }
            }
        else:
            return {
                'statusCode': 401,
                'body': 'Expired RefreshToken'
            }

    def checkID(cls,username):
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
        if boolean_value == 1:
            return {
                'statusCode': 200,
                'body': 'Success!!!!'
            }
        else:
            return {
                'statusCode': 401,
                'body': 'Not equals ID'
            }

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

#def getAccessToken(grant, userId):


def handler(event):
    # 보안 인증서 발급
    grant = es.login(event['userId'], event['password'])
    time.sleep(1)

    # 로그인 검증 실패 시
    if (grant['statusCode'] == 401):
        return grant

    # 로그인 검증 성공 시(보안 인증서 발급)
    else:
        # 인증서 검증
        compG = es.checkGrants(grant['body']['grants'])

        # 인증서 검증 실패 시
        if compG['statusCode'] == 401:
            return compG
        
        # 인증서 검증 성공 시
        else:
            created = compG['body']['created']
            encoded = grant['body']['grants']
            # 암호화된 인증서 디코드
            decoded = jwt.decode(
                encoded,
                ''+event['userId']+created,
                algorithms = ['HS256']
            )
            
            # 디코딩 결과의 userId와 DB의 userId가 다른 경우
            if decoded['userId'] != event['userId']:
                return {
                    'statusCode': 401,
                    'body': 'UserId not equals'
                }

            # 디코딩 결과의 userId와 DB의 userId가 같은 경우
            else:
                # 인증서 삭제
                es.grants_delete(decoded['userId'])

                # 액세스, 리프레시 토큰 발급
                token = es.tokens_dataInsert(decoded['userId'])

                # 액세스 토큰 검증
                comT = es.checkTokens(token['body']['accessToken'])

                if comT['statusCode'] == 401:
                    return comT

                else:
                    at = comT['body']['expired_accessToken']
                    dt = parse(at)
                    nd = datetime.now()
                    
                    # 액세스 토큰 만료 시
                    if nd > dt:
                        returnValue = {
                            'statusCode': 403,
                            'body': 'Expired accessToken'
                        }
                    
                    else:
                        decodeAt = jwt.decode(
                            token['body']['accessToken'],
                            ''+event['userId'],
                            algorithms = ['HS256']
                        )
                        check = es.checkID(decodeAt['userId'])

                        # 엑세스 토큰 검증 성공 또는 실패 시
                        return check
                
                # 액세스 토큰 만료 시
                if returnValue['statusCode'] == 403:

                    checkRt = es.checkReTokens(token['body']['refreshToken'])
                    if checkRt['statusCode'] == 200:
                        print(checkRt)
                        at = checkRt['body']['expired_refreshToken']
                        dt = parse(at)
                        nd = datetime.now()

                        if nd > dt:
                            returnValue = {
                                'statusCode': 403,
                                'body': 'Expired refreshToken'
                            }

                        else:
                            decodedRt = jwt.decode(
                                token['body']['refreshToken'],
                                ''+event['userId'],
                                algorithms = ['HS256']
                            )
                            check = es.checkID(decodedRt['userId'])

                            if check == 1:
                                es.tokens_delete(decodedRt['userId'])
                                final = es.tokens_dataInsert(decodedRt['userId'])
                                print('final')
                                print(final)
                                return {
                                    'statusCode': 200,
                                    'body': {
                                        'accessToken': final['body']['accessToken'],
                                        'refreshToken': final['body']['refreshToken']
                                    }
                                }

                            else:
                                return {
                                    'statusCode': 401,
                                    'body': 'Not equals ID'
                                }

                            



if __name__ == "__main__":
    handler({'userId': 'hanseol', 'password': '123456'})