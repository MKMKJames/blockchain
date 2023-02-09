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

import json
import sys
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import ZR, G1, GT, pair
from charm.core.math.integer import integer, int2Bytes, randomBits, serialize, deserialize
from charm.toolbox.hash_module import Hash
from charm.core.engine.util import objectToBytes, bytesToObject

debug = False


class PreGA:
    def __init__(self):
        global group, h, params
        group = PairingGroup('SS512', secparam=1024)
        h = Hash(group)
        params = self.getParams()

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

    def deserialize_params(self, raw):
        data = eval(raw)
        return {'g': bytesToObject(data['g'], group), 'g_s': bytesToObject(data['g_s'], group)}

    def decrypt(self, skid, IDsrc, ID, cid):
        K = pair(group.hash(IDsrc, G1), skid)
        sigma = cid['B'] * \
            pair(cid['A'], group.hash((K, IDsrc, ID, cid['N']), G1))
        m = cid['C'] ^ h.hashToZn(sigma)
        r = h.hashToZr(sigma, m)
        if (cid['A'] != params['g'] ** r):
            return None
        return int2Bytes(m)

    def deserialize_ctext2(self, raw):
        data = eval(raw)
        return {'A': bytesToObject(data['A'], group),
                'B': bytesToObject(data['B'], group),
                'C': deserialize(data['C']),
                'IDsrc': data['IDsrc'],
                'N': deserialize(data['N'])}

    def deserialize_sk(self, raw):
        data = eval(raw)
        return bytesToObject(data, group)

    def serialize_rk(self, rk):
        return str({'N': serialize(rk['N']), 'R': objectToBytes(rk['R'], group)})

    def rkGen(self, skid, IDsrc, IDdest):
        N = integer(randomBits(group.secparam))
        K = pair(skid, group.hash(IDdest, G1))
        return {'N': N, 'R': group.hash((K, IDsrc, IDdest, N), G1) * skid}


if __name__ == '__main__':
    pre = PreGA()
    method = sys.argv[1]
    if method == 'rkGen':
        sk1 = sys.argv[2]
        id1 = sys.argv[3]
        id2 = sys.argv[4]
        print(pre.serialize_rk(pre.rkGen(pre.deserialize_sk(sk1), id1, id2)), end='')
    elif method == 'decrypt':
        sk2 = pre.deserialize_sk(sys.argv[2])
        id1 = sys.argv[3]
        id2 = sys.argv[4]
        cmsg = pre.deserialize_ctext2(sys.argv[5])
        print(json.dumps(eval(pre.decrypt(sk2, id1, id2, cmsg))), end='')
    else:
        exit(-1)
