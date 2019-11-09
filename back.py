from elasticsearch import Elasticsearch
import pprint as ppr
import json
import random
import jwt
import time
from datetime import datetime,timedelta
from dateutil.parser import parse

class ElaAPI:
    # 객체 생성
    es = Elasticsearch(hosts="54.180.97.228", port=9200)

    # 보안 인증서 삽입
    # @param {string} userId
    # @return {Object} status massege and encoded grantId
    def grants_dataInsert(cls,userId):
        # init datetime
        now = datetime.now()
        current = str(now.isoformat())
        next_current = str(now+timedelta(seconds=5))

        # grant id encoding 
        encodedId = jwt.encode(
            {
                'userId': userId,
                'created': current
            },
            ''+userId+current,
            algorithm = 'HS256'
        ).decode('utf-8')
        encodedId = str(encodedId)

        # create grants_data
        grants_data = {
            "id" : encodedId,
            "created" : current,
            "expired" : next_current
        }

        # search userId
        res = cls.es.search(
            index = "grants",
            body = {
                "query": {
                    "match" : {
                        "_id" : userId
                    }
                }
            })

        boolean_value = res["hits"]["total"]["value"]

        # userId가 DB에 없는 경우
        if boolean_value == 0:
            cls.es.index(index="grants",doc_type="_doc",id=userId,body=grants_data)
            return {
                'statusCode': 200,
                'body': {
                    'grants': encodedId
                }
            }

        # userId가 DB에 있는 경우
        else:
            for i in range(len(res["hits"]["hits"])):
                if res["hits"]["hits"][i]["_id"] == userId:
                    return {
                        'statusCode': 200,
                        'body': {
                            'grants': res['hits']['hits'][i]['_source']['id']
                        }
                    }
    
    # 보안 인증서 삭제
    # @param {string} userId 
    def grants_delete(cls,userId):
        cls.es.delete(index="grants",doc_type="_doc",id=userId)
    

    # 토큰 삽입
    # @param {string} event.userId
    # @return {Object} status massege and encoded tokens
    def tokens_dataInsert(cls,userId):
        # init datetime
        now = datetime.now()
        expired_accessToken = str(now+timedelta(hours=1))
        expired_refreshToken = str(now+timedelta(hours=12))

        # accessToken encoding
        accessToken = jwt.encode(
            {
                'userId': userId,
                'expired_accessToken': expired_accessToken
            },
            ''+userId,
            algorithm = 'HS256'
        ).decode('utf-8')

        # refreshToken encoding
        refreshToken = jwt.encode(
            {
                'userId': userId,
                'expired_refreshToken': expired_refreshToken
            },
            ''+userId,
            algorithm = 'HS256'
        ).decode('utf-8')

        # create tokens_data
        tokens_data = {
            "accessToken" : accessToken,
            "refreshToken" : refreshToken,
            "expired_accessToken" : expired_accessToken,
            "expired_refreshToken" : expired_refreshToken
        }

        # search userId
        res = cls.es.search(
            index = "tokens",
            body = {
                "query": {
                    "match" : {
                        "_id" : userId
                    }
                }
            })

        boolean_value = res["hits"]["total"]["value"]

        # userId가 DB에 없는 경우
        if boolean_value == 0:
            res = cls.es.index(index="tokens",doc_type="_doc",id=userId,body=tokens_data)
            return {
                'statusCode': 200,
                'body': {
                    'accessToken': accessToken,
                    'refreshToken': refreshToken
                }
            }

        # userId가 DB에 있는 경우
        else:
            for i in range(len(res["hits"]["hits"])):
                if res["hits"]["hits"][i]["_id"] == userId:
                    return {
                        'statusCode': 200,
                        'body': {
                            'accessToken': res["hits"]["hits"][i]["_source"]["accessToken"],
                            'refreshToken': res["hits"]["hits"][i]["_source"]["refreshToken"]
                        }
                    }
    
    # 토큰 삭제
    # @param {string} userId
    def tokens_delete(cls,userId):
        # search userId
        res = cls.es.search(
                index = "users",
                body = {
                    "query": {
                        "match" : {
                            "_id" : userId
                        }
                    }
                })
        boolean_value = res["hits"]["total"]["value"]
        
        # userId가 DB에 있는 경우
        if boolean_value == 1:
            cls.es.delete(index="tokens",doc_type="_doc",id=userId)


    # login
    # @param {string} userId
    # @param {string} passwd
    # @return {Object} status massege
    def login(cls,userId,passwd):
        # search userId
        res = cls.es.search(
                index = "users",
                body = {
                    "query": {
                        "match" : {
                            "_id" : userId
                        }
                    }
                })
        boolean_value = res["hits"]["total"]["value"]
        
        # 아이디 O
        if boolean_value == 1:
            ps = res["hits"]["hits"][0]["_source"]["password"]

            # 비밀번호 O
            if passwd == ps:
                grantsId = cls.grants_dataInsert(userId)
                return grantsId

            # 비밀번호 X
            else:
                return {
                    'statusCode': 401,
                    'body': 'Invalid user'
                }

        # 아이디 X
        else:
            return {
                'statusCode': 401,
                'body': 'Invalid user'
            }

    # check whether grant exists
    # @param {string} grant grant id
    # @return {Object} status massege
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

        # grant가 DB에 있는 경우
        if comp == True:
            return {
                'statusCode': 200,
                'body': {
                    'userId': data["hits"]["hits"][i]["_id"],
                    'created': data["hits"]["hits"][i]['_source']['created']
                }
            }

        # grant가 DB에 없는 경우
        else:
            return {
                'statusCode': 401,
                'body': 'Invalid userId'
            }

    # check whether access token exists
    # @param {string} token access token
    # @return {Object} status massege
    def checkTokens(cls,token):
        res = cls.es.search(
            index = "tokens",
            body = {
                "query":{"match_all":{}}
            }
        )
        data = json.dumps(res, ensure_ascii=False, indent=4)
        data = json.loads(data)
        comp = False
        for i in range(len(data["hits"]["hits"])):
            if data["hits"]["hits"][i]["_source"]["accessToken"] == token:
                comp = True
                break
        
        # grant가 DB에 있는 경우
        if comp == True:
            return {
                'statusCode': 200,
                'body': {
                    'userId': data["hits"]["hits"][i]["_id"],
                    'expired_accessToken': data["hits"]["hits"][i]["_source"]["expired_accessToken"]
                }
            }

        # grant가 DB에 없는 경우
        else:
            return {
                'statusCode': 401,
                'body': 'Invalid user'
            }

    # check whether refresh token exists
    # @param {string} token refresh token
    # @return {Object} status massege
    def checkReTokens(cls,refreshToken):
        res = cls.es.search(
            index = "tokens",
            body = {
                "query":{"match_all":{}}
            }
        )
        data = json.dumps(res, ensure_ascii=False, indent=4)
        data = json.loads(data)
        comp = False
        for i in range(len(data["hits"]["hits"])):
            if data["hits"]["hits"][i]["_source"]["refreshToken"] == refreshToken:
                comp = True
                break
        
        # grant가 DB에 있는 경우
        if comp == True:
            return {
                'statusCode': 200,
                'body': {
                    'userId': data["hits"]["hits"][i]["_id"],
                    'expired_refreshToken': data["hits"]["hits"][i]["_source"]["expired_refreshToken"]
                }
            }

        # grant가 DB에 없는 경우
        else:
            return {
                'statusCode': 401,
                'body': 'Invalid User'
            }

    # check whether user id exists
    # @param {string} userId
    # @return {Object} status massege
    def checkID(cls,userId):
        # search userId
        res = cls.es.search(
                index = "users",
                body = {
                    "query": {
                        "match" : {
                            "_id" : userId
                        }
                    }
                })

        boolean_value = res["hits"]["total"]["value"]
        
        # userId가 DB에 있는 경우
        if boolean_value == 1:
            return {
                'statusCode': 200,
                'body': 'Success!!!!'
            }

        # userId가 DB에 없는 경우
        else:
            return {
                'statusCode': 401,
                'body': 'Invalid user'
            }

# 객체 생성
es = ElaAPI()

# @param {Object} event user account
# @param {string} event.userId user id
# @param {string} event.password user password
# @return {Object} status message
def handler(event):
    userId = event['userId']
    passwd = event['password']

    # 보안 인증서 발급
    grant = es.login(userId, passwd) # 로그인
    time.sleep(1)

    # 로그인 검증 실패 시
    if (grant['statusCode'] == 401):
        return grant

    # 로그인 검증 성공 시(보안 인증서 발급)
    else:
        grantId = grant['body']['grants']
        
        # 인증서 검증
        compG = es.checkGrants(grantId)

        # 인증서 검증 실패 시
        if compG['statusCode'] == 401:
            return compG
        
        # 인증서 검증 성공 시
        else:
            created = compG['body']['created']

            # 암호화된 인증서 디코드
            decoded = jwt.decode(
                grantId,
                ''+userId+created,
                algorithms = ['HS256']
            )

            decode_userId = decoded['userId']
            # 디코딩 결과의 userId와 DB의 userId가 다른 경우
            if decoded_userId != userId:
                return {
                    'statusCode': 401,
                    'body': 'Invalid user'
                }

            # 디코딩 결과의 userId와 DB의 userId가 같은 경우
            else:
                # 인증서 삭제
                es.grants_delete(decoded_userId)

                # 액세스, 리프레시 토큰 발급
                token = es.tokens_dataInsert(decoded_userId)

                # 액세스 토큰 검증
                time.sleep(1)
                comT = es.checkTokens(token['body']['accessToken'])

                if comT['statusCode'] == 401:
                    return comT

                else:
                    # expired_accessToken_time
                    at = comT['body']['expired_accessToken']

                    # Type: string to datetime
                    dt = parse(at)

                    # current time
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
                            ''+userId,
                            algorithms = ['HS256']
                        )
                        check = es.checkID(decodeAt['userId'])

                        # 엑세스 토큰으로 아이디 검증 성공 또는 실패 시
                        return check
                
                # 액세스 토큰 만료 시
                if returnValue['statusCode'] == 403:
                    # 리프레시 토큰 검증
                    checkRt = es.checkReTokens(token['body']['refreshToken'])
                    
                    # 검증 실패 시
                    if checkRt['statusCode'] == 401:
                        return checkRt
                    
                    # 검증 성공 시
                    else:
                        # expired_refreshToken_time
                        at = checkRt['body']['expired_refreshToken']

                        # Type: string to datetime
                        dt = parse(at)

                        # current time
                        nd = datetime.now()

                        # 리프레시 토큰 만료 시
                        if nd > dt:
                            returnValue = {
                                'statusCode': 403,
                                'body': 'Expired refreshToken'
                            }

                        else:
                            decodedRt = jwt.decode(
                                token['body']['refreshToken'],
                                ''+userId,
                                algorithms = ['HS256']
                            )

                            decoded_userId = decodedRt['userId']

                            check = es.checkID(decoded_userId)
                            # 리프레시 토큰으로 아이디 검증 성공 시
                            if check == 1:
                                # 토큰 제거
                                es.tokens_delete(decoded_userId)
                                # 토큰 삽입
                                final = es.tokens_dataInsert(decoded_userId)
                                return {
                                    'statusCode': 200,
                                    'body': {
                                        'accessToken': final['body']['accessToken'],
                                        'refreshToken': final['body']['refreshToken']
                                    }
                                }

                            # 리프레시 토큰으로 아이디 검증 실패 시
                            else:
                                return {
                                    'statusCode': 401,
                                    'body': 'Invalid user'
                                }

if __name__ == "__main__":
    handler({'userId': 'test', 'password': '1234'})