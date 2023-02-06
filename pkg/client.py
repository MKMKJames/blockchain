import requests

# import json
# d = dict(name='Bob', age=20, score=88)
# print(json.dumps(d)


def alice_regist():
    url = "http://127.0.0.1:8888/keyGen"
    data = {
        "id": "alice"
    }
    response = requests.post(url, data=data)
    return response.text


def bob_regist():
    url = "http://127.0.0.1:8888/keyGen"
    data = {
        "id": "bob"
    }
    response = requests.post(url, data=data)
    return response.text


def alice_encrypt(msg):
    url = "http://127.0.0.1:8888/encrypt"
    data = {
        "id": "alice",
        'msg': msg
    }
    response = requests.post(url, data=data)
    return response.text


def rkGen(sk1):
    url = "http://127.0.0.1:8888/rkGen"
    data = {
        'sk1': sk1,
        "id1": "alice",
        'id2': 'bob'
    }
    response = requests.post(url, data=data)
    return response.text


def reEncrypt(id, rk, cmsg):
    url = "http://127.0.0.1:8888/reEncrypt"
    data = {
        "id": id,
        'rk': rk,
        'cmsg': cmsg
    }
    response = requests.post(url, data=data)
    return response.text


def decrypt(sk2, id1, id2, cmsg):
    url = "http://127.0.0.1:8888/decrypt"
    data = {
        'sk2': sk2,
        'id1': id1,
        'id2': id2,
        'cmsg': cmsg
    }
    response = requests.post(url, data=data)
    return response.text


sk1 = alice_regist()
sk2 = bob_regist()

# print(sk1)

msg = '对方hi额34242423432234u文化iu文化我gieur江r手r絵rfg 儿童额头热天我微软 发士大夫士大夫五2 2 人房贷首付dsdf st43242342342332423fdgdfgfdfgdfgertertくぇれww絵wr123😀!!!！！'

ctext1 = alice_encrypt(msg)
# print(ctext1)
rk = rkGen(sk1)
# print(rk)

ctexe2 = reEncrypt('alice', rk, ctext1)
# print(ctexe2)

result = decrypt(sk2, 'alice', 'bob', ctexe2)

print(msg)
print(eval(result))