'''
Identity-Based Proxy Re-Encryption

| From: "M. Green, G. Ateniese Identity-Based Proxy Re-Encryption", Section 4.3.
| Published in: Applied Cryptography and Network Security. Springer Berlin/Heidelberg, 2007
| Available from: http://link.springer.com/chapter/10.1007%2F978-3-540-72738-5_19

* type:           proxy encryption (identity-based)
* setting:        bilinear groups (symmetric)

:Authors:    N. Fotiou
:Date:       11/2012
'''

from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import ZR, G1, GT, pair
from charm.core.math.integer import integer, int2Bytes, randomBits, serialize, deserialize
from charm.toolbox.hash_module import Hash
from charm.core.engine.util import objectToBytes, bytesToObject
import json


class PreGA:
    def __init__(self):
        global group, h
        group = PairingGroup('SS512', secparam=1024)
        h = Hash(group)

    def getParams(self):
        try:
            with open('./params', 'r') as f:
                params = json.loads(f.read())
                try:
                    return self.deserialize_params((params['params']))
                except:
                    print('fail to convert')
                    exit(-1)
        except Exception as e:
            print('proxy: cannot find ./params', e)
            exit(-1)

    def setup(self):
        return self.getParams()

    def keyGen(self, msk, ID):
        k = group.hash(ID, G1) ** msk['s']
        return k

    def serialize_sk(self, obj):
        return str(objectToBytes(obj, group))

    def deserialize_sk(self, raw):
        data = eval(raw)
        return bytesToObject(data, group)

    def serialize_rk(self, rk):
        return str({'N': serialize(rk['N']), 'R': objectToBytes(rk['R'], group)})

    def deserialize_rk(self, raw):
        data = eval(raw)
        return {'N': deserialize(data['N']), 'R': bytesToObject(data['R'], group)}

    def serialize_params(self, obj):
        return str({'g': objectToBytes(obj['g'], group), 'g_s': objectToBytes(obj['g_s'], group)})

    def deserialize_params(self, raw):
        data = eval(raw)
        return {'g': bytesToObject(data['g'], group), 'g_s': bytesToObject(data['g_s'], group)}

    def rkGen(self, params, skid, IDsrc, IDdest):
        N = integer(randomBits(group.secparam))
        K = pair(skid, group.hash(IDdest, G1))
        return {'N': N, 'R': group.hash((K, IDsrc, IDdest, N), G1) * skid}

    def serialize_ctext1(self, obj):
        return str({'S': objectToBytes(obj['S'], group),
                    'C': {
                    'A': objectToBytes(obj['C']['A'], group),
                    'B': objectToBytes(obj['C']['B'], group),
                    'C': serialize(obj['C']['C'])}})

    def deserialize_ctext1(self, raw):
        data = eval(raw)
        return {'S': bytesToObject(data['S'], group),
                'C': {
                    'A': bytesToObject(data['C']['A'], group),
                    'B': bytesToObject(data['C']['B'], group),
                    'C': deserialize(data['C']['C'])}}

    def serialize_ctext2(self, obj):
        return str({'A': objectToBytes(obj['A'], group),
                    'B': objectToBytes(obj['B'], group),
                    'C': serialize(obj['C']),
                    'IDsrc': obj['IDsrc'],
                    'N': serialize(obj['N'])})

    def deserialize_ctext2(self, raw):
        data = eval(raw)
        return {'A': bytesToObject(data['A'], group),
                'B': bytesToObject(data['B'], group),
                'C': deserialize(data['C']),
                'IDsrc': data['IDsrc'],
                'N': deserialize(data['N'])}

    # 同一份参数，每次加密的结果都不一样
    def encrypt(self, params, ID, M):
        enc_M = integer(M)
        # if bitsize(enc_M)/8 > group.messageSize():
        #     print("Message cannot be encoded.")
        #     return None
        sigma = group.random(GT)
        r = h.hashToZr(sigma, enc_M)
        A = params['g'] ** r
        B = sigma * pair(params['g_s'], group.hash(ID, G1) ** r)
        C = enc_M ^ h.hashToZn(sigma)
        C_ = {'A': A, 'B': B, 'C': C}
        S = group.hash((ID, C_), G1) ** r
        ciphertext = {'S': S, 'C': C_}
        return ciphertext

    # 同一份参数，每次加密的结果都不一样
    def reEncrypt(self, params, IDsrc, rk, cid):
        H = group.hash((IDsrc, cid['C']), G1)
        if pair(params['g'], cid['S']) != pair(H, cid['C']['A']):
            return None
        t = group.random(ZR)
        B_ = cid['C']['B'] / (pair(cid['C']['A'], rk['R']
                              * H ** t)/pair(params['g'] ** t, cid['S']))
        return {'A': cid['C']['A'], 'B': B_, 'C': cid['C']['C'], 'IDsrc': IDsrc, 'N': rk['N']}

    def decryptSecondLevel(self, params, skid, IDsrc, ID, cid):
        K = pair(group.hash(IDsrc, G1), skid)
        sigma = cid['B'] * \
            pair(cid['A'], group.hash((K, IDsrc, ID, cid['N']), G1))
        m = cid['C'] ^ h.hashToZn(sigma)
        r = h.hashToZr(sigma, m)
        if (cid['A'] != params['g'] ** r):
            return None
        return int2Bytes(m)


debug = False

if debug:
    ID = "nikos fotiou"
    ID2 = "test user"
    msg = '{"Key":"Ss4OXQlZO5sjEgcSKjSAaIRlc_FvB9Qm0oJZXmUm3lc=","Location":"/alice/hello.txt"}'
    # print('msgsz: ', len(msg), bitsize(integer(msg))/8)
    pre = PreGA()
    (master_secret_key, params) = pre.setup()

    # 根据ID生成私钥
    id_secret_key = pre.keyGen(master_secret_key, ID)
    id2_secret_key = pre.keyGen(master_secret_key, ID2)

    # 使用ID加密数据
    ciphertext = pre.encrypt(params, ID, msg)

    # print(ciphertext)

    # # pre.decryptFirstLevel(params, id_secret_key, ciphertext, ID)

    # 使用对方ID生成重加密key
    re_encryption_key = pre.rkGen(params, id_secret_key, ID, ID2)

    # 利用重加密key加密密文
    ciphertext2 = pre.reEncrypt(params, ID, re_encryption_key, ciphertext)

    # print(ciphertext2)

    # 对方可以用自己的ID解密
    m = pre.decryptSecondLevel(params, id2_secret_key, ID, ID2, ciphertext2)

    print(msg)
    print(str(m, 'utf-8'))
