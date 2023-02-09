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
        global group
        group = PairingGroup('SS512', secparam=1024)

    def getParams(self):
        try:
            with open('./params', 'r') as f:
                s_params = json.loads(f.read())
                try:
                    s = bytesToObject(eval(s_params['s']), group)
                    params = self.deserialize_params((s_params['params']))
                    return {'s': s, 'params': params}
                except:
                    print('fail to convert')
                    exit(-1)
        except:
            with open('./params', 'w') as f:
                s = group.random(ZR)
                g = group.random(G1)
                params = {'g': g, 'g_s': g**s}
                dict = {'s': str(objectToBytes(s, group)),
                        'params': self.serialize_params(params)}
                f.write(json.dumps(dict))
                return {'s': s, 'params': params}

    def setup(self):
        s_params = self.getParams()
        s, params = s_params['s'], s_params['params']
        return ({'s': s}, params)

    def keyGen(self, msk, ID):
        k = group.hash(ID, G1) ** msk['s']
        return k

    def serialize_sk(self, obj):
        return str(objectToBytes(obj, group))

    def serialize_params(self, obj):
        return str({'g': objectToBytes(obj['g'], group), 'g_s': objectToBytes(obj['g_s'], group)})

    def deserialize_params(self, raw):
        data = eval(raw)
        return {'g': bytesToObject(data['g'], group), 'g_s': bytesToObject(data['g_s'], group)}

debug = False

if debug:
    pre = PreGA()
    (sk, params) = pre.setup()
    print(params)
    print(pre.deserialize_params(pre.serialize_params(params)))
