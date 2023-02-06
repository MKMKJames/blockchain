import flask
import json
import IBPRE as pre
from flask import request


class Util:
    def __init__(self) -> None:
        self.proxy = pre.PreGA()
        (self.master_secret_key, self.params) = self.proxy.setup()

    def keyGen(self, id):
        sk = self.proxy.keyGen(self.master_secret_key, id)
        return self.serialize_sk(sk)

    def encrypt(self, id, msg):
        return self.serialize_ctext1(self.proxy.encrypt(self.params, id, msg))

    def rkGen(self, sk1, id1, id2):
        return self.serialize_rk(self.proxy.rkGen(self.params, self.deserialize_sk(sk1), id1, id2))

    def reEncrypt(self, id, rk, cmsg):
        des_rk = self.deserialize_rk(rk)
        des_cmsg = self.deserialize_ctext1(cmsg)
        return self.serialize_ctext2(self.proxy.reEncrypt(self.params, id, des_rk, des_cmsg))

    def decrypt(self, sk2, id1, id2, cmsg):
        return self.proxy.decryptSecondLevel(self.params, self.deserialize_sk(sk2), id1, id2, self.deserialize_ctext2(cmsg))

    def serialize_sk(self, data):
        return self.proxy.serialize_sk(data)

    def deserialize_sk(self, data):
        return self.proxy.deserialize_sk(data)

    def serialize_rk(self, data):
        return self.proxy.serialize_rk(data)

    def deserialize_rk(self, data):
        return self.proxy.deserialize_rk(data)

    def serialize_ctext1(self, data):
        return self.proxy.serialize_ctext1(data)

    def deserialize_ctext1(self, data):
        return self.proxy.deserialize_ctext1(data)

    def serialize_ctext2(self, data):
        return self.proxy.serialize_ctext2(data)

    def deserialize_ctext2(self, data):
        return self.proxy.deserialize_ctext2(data)


# 创建一个服务，把当前这个python文件当做一个服务
server = flask.Flask(__name__)
util = Util()

@server.route('/keyGen', methods=['post'])
def keyGen():
    id = request.form['id']
    return json.dumps(util.keyGen(id), ensure_ascii=False)

@server.route('/encrypt', methods=['post'])
def encrypt():
    id = request.form['id']
    msg = request.form['msg']
    return json.dumps(util.encrypt(id, msg), ensure_ascii=False)

@server.route('/rkGen', methods=['post'])
def rkGen():
    id1 = request.form['id1']
    id2 = request.form['id2']
    sk1 = eval(request.form['sk1'])
    return json.dumps(util.rkGen(sk1, id1, id2), ensure_ascii=False)

@server.route('/reEncrypt', methods=['post'])
def reEncrypt():
    id = request.form['id']
    rk = eval(request.form['rk'])
    cmsg = eval(request.form['cmsg'])
    return json.dumps(util.reEncrypt(id, rk, cmsg), ensure_ascii=False)


@server.route('/decrypt', methods=['post'])
def decrypt():
    sk2 = eval(request.form['sk2'])
    id1 = request.form['id1']
    id2 = request.form['id2']
    cmsg = eval(request.form['cmsg'])
    dec = util.decrypt(sk2, id1, id2, cmsg)
    return json.dumps(str(dec, 'utf-8'), ensure_ascii=False)


if __name__ == '__main__':
    # 指定端口,host,0.0.0.0代表不管几个网卡，任何ip都可访问
    server.run(debug=True, port=8888, host='0.0.0.0')
