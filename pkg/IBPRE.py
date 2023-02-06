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
        self.group = PairingGroup('SS512', secparam=1024)

    def getParams(self):
        try:
            with open('./params', 'r') as f:
                params = json.loads(f.read())
                try:
                    s = bytesToObject(eval(params['s']), self.group)
                    g = bytesToObject(eval(params['g']), self.group)
                    return {'s': s, 'g': g}
                except:
                    print('fail to convert')
                    exit(-1)
        except:
            with open('./params', 'w') as f:
                s = self.group.random(ZR)
                g = self.group.random(G1)
                dict = {'s': str(objectToBytes(s, self.group)),
                        'g': str(objectToBytes(g, self.group))}
                f.write(json.dumps(dict))
                return {'s': s, 'g': g}

    def setup(self):
        params = self.getParams()
        s, g = params['s'], params['g']
        return ({'s': s}, {'g': g, 'g_s': g**s})

    def keyGen(self, msk, ID):
        k = self.group.hash(ID, G1) ** msk['s']
        return k

    def serialize_sk(self, obj):
        return str(objectToBytes(obj, self.group))


# data = {'hello':'world'}
# j1 = json.dumps(data)
# print(j1)

# print(json.dumps(j1))