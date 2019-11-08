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

    '''
        # 보안 인증서 삽입
        # @param {string} event.userId user id
        # @return {Object} status massege
    ''' 
    def grants_dataInsert(cls,username):
        # init datetime
        now = datetime.now()
        current = str(now.isoformat())
        next_current = str(now+timedelta(seconds=5))
        # grant id encoding 
        encodedId = jwt.encode(
            {
                'userId': username,
                'created': current
            },
            ''+username+current,
            algorithm = 'HS256'
        ).decode('utf-8')
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
        # userId가 DB에 없는 경우
        if boolean_value == 0:
            return {
                'statusCode': 200,
                'body': {
                    'grants': encodedId
                }
            }
        # userId가 DB에 있는 경우
        else:
            for i in range(len(res["hits"]["hits"])):
                if res["hits"]["hits"][i]["_id"] == username:
                    return {
                        'statusCode': 200,
                        'body': {
                            'grants': res['hits']['hits'][i]['_source']['id']
                        }
                    }
    
    '''
        # 보안 인증서 삭제
        # @param {string} event.userId user id
    ''' 
    def grants_delete(cls,username):
        cls.es.delete(index="grants",doc_type="_doc",id=username)
    
    '''
        # 토큰 삽입
        # @param {string} event.userId user id
        # @return {Object} status massege
    ''' 
    def tokens_dataInsert(cls,username):
        # init datetime
        now = datetime.now()
        expired_accessToken = str(now+timedelta(hours=1))
        expired_refreshToken = str(now+timedelta(hours=12))
        # accessToken encoding
        accessToken = jwt.encode(
            {
                'userId': username,
                'expired_accessToken': expired_accessToken
            },
            ''+username,
            algorithm = 'HS256'
        ).decode('utf-8')
        # refreshToken encoding
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
        # userId가 DB에 없는 경우
        if boolean_value == 0:
            res = cls.es.index(index="tokens",doc_type="_doc",id=username,body=tokens_data)
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
                if res["hits"]["hits"][i]["_id"] == username:
                    return {
                        'statusCode': 200,
                        'body': {
                            'accessToken': res["hits"]["hits"][i]["_source"]["accessToken"],
                            'refreshToken': res["hits"]["hits"][i]["_source"]["refreshToken"]
                        }
                    }
    
    '''
        # 토큰 삭제
        # @param {string} event.userId user id
    '''
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
            cls.es.delete(index="tokens",doc_type="_doc",id=username)


    '''
        # login
        # @param {string} event.userId user id
        # @param {string} event.password user password
        # @return {Object} status massege
    '''
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
                grantsId = cls.grants_dataInsert(username)
                return grantsId
            # 비밀번호 X
            else:
                return {
                    'statusCode': 401,
                    'body': 'Incorrect password'
                }
        # 아이디 X
        else:
            return {
                'statusCode': 401,
                'body': 'There is no userId'
            }

    '''
        # check whether grant exists
        # @param {string} grant.body.grants grant id
        # @return {Object} status massege
    '''
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

    '''
        # check whether access token exists
        # @param {string} token.body.accessToken access token
        # @return {Object} status massege
    '''
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
                'statusCode': 200,
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

    '''
        # check whether refresh token exists
        # @param {string} token.body.refreshToken refresh token
        # @return {Object} status massege
    '''
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

    '''
        # check whether user id exists
        # @param {string} event.userId user id
        # @return {Object} status massege
    '''
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

# 객체 생성
es = ElaAPI()

'''
    # @param {Object} event user account
    # @param {string} event.userId user id
    # @param {string} event.password user password
    # @return {Object} status message
'''
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
                time.sleep(1)
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
                        at = checkRt['body']['expired_refreshToken']
                        dt = parse(at)
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
                                ''+event['userId'],
                                algorithms = ['HS256']
                            )
                            check = es.checkID(decodedRt['userId'])
                            # 리프레시 토큰으로 아이디 검증 성공 시
                            if check == 1:
                                # 토큰 제거
                                es.tokens_delete(decodedRt['userId'])
                                # 토큰 삽입
                                final = es.tokens_dataInsert(decodedRt['userId'])
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
                                    'body': 'Not equals ID'
                                }

if __name__ == "__main__":
    handler({'userId': 'test', 'password': '1234'})