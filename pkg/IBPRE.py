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

debug = False


class PreGA:
    def __init__(self):
        global group, h
        group = PairingGroup('SS512', secparam=1024)
        h = Hash(group)

    def setup(self):
        s = group.random(ZR)
        g = group.random(G1)
        # choose H1-H6 hash functions
        msk = {'s': s}
        params = {'g': g, 'g_s': g**s}
        return (msk, params)

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

    def rkGen(self, params, skid, IDsrc, IDdest):
        N = integer(randomBits(group.secparam))
        K = pair(skid, group.hash(IDdest, G1))
        return {'N': N, 'R': group.hash((K, IDsrc, IDdest, N), G1) * skid}

# ID = "nikos fotiou"
# ID2 = "test user"
# msg = '对方hi额34242423432234u文化iu文化我gieur江r手r絵rfg 儿童额头热天我微软 发士大夫士大夫五2 2 人房贷首付dsdf st43242342342332423fdgdfgfdfgdfgertertくぇれww絵wr123😀!!!！！'
# # print('msgsz: ', len(msg), bitsize(integer(msg))/8)
# pre = PreGA()
# (master_secret_key, params) = pre.setup()

# # 根据ID生成私钥
# id_secret_key = pre.keyGen(master_secret_key, ID)
# id2_secret_key = pre.keyGen(master_secret_key, ID2)

# # 使用ID加密数据
# ciphertext = pre.encrypt(params, ID, msg)

# print(ciphertext)

# # # pre.decryptFirstLevel(params, id_secret_key, ciphertext, ID)

# # 使用对方ID生成重加密key
# re_encryption_key = pre.rkGen(params, id_secret_key, ID, ID2)

# # 利用重加密key加密密文
# ciphertext2 = pre.reEncrypt(params, ID, re_encryption_key, ciphertext)

# print(ciphertext2)

# # 对方可以用自己的ID解密
# m = pre.decryptSecondLevel(params, id2_secret_key, ID, ID2, ciphertext2)

# print(msg)
# print(str(m, 'utf-8'))
