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

import sys
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

    def serialize_rk(self, rk):
        return str({'N': serialize(rk['N']), 'R': objectToBytes(rk['R'], group)})

    def deserialize_sk(self, raw):
        data = eval(raw)
        return bytesToObject(data, group)

    def rkGen(self, skid, IDsrc, IDdest):
        N = integer(randomBits(group.secparam))
        K = pair(skid, group.hash(IDdest, G1))
        return {'N': N, 'R': group.hash((K, IDsrc, IDdest, N), G1) * skid}


if __name__ == '__main__':
    pre = PreGA()
    sk1 = sys.argv[1]
    id1 = sys.argv[2]
    id2 = sys.argv[3]
    # with open('./secret_key_' + id1, 'r') as f:
    #     s = f.read()
    #     sk = pre.deserialize_sk(eval(s))
    print('\"' + pre.serialize_rk(pre.rkGen(pre.deserialize_sk(eval(sk1)), id1, id2)) + '\"', end='')
