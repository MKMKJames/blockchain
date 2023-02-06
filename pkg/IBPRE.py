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

    def getParams(self):
        try:
            with open('./params', 'r') as f:
                params = json.loads(f.read())
                try:
                    s = bytesToObject(eval(params['s']), group)
                    g = bytesToObject(eval(params['g']), group)
                    return {'s': s, 'g': g}
                except:
                    print('fail to convert')
                    exit(-1)
        except:
            with open('./params', 'w') as f:
                s = group.random(ZR)
                g = group.random(G1)
                dict = {'s': str(objectToBytes(s, group)),
                        'g': str(objectToBytes(g, group))}
                f.write(json.dumps(dict))
                return {'s': s, 'g': g}

    def setup(self):
        params = self.getParams()
        s, g = params['s'], params['g']
        return ({'s': s}, {'g': g, 'g_s': g**s})

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