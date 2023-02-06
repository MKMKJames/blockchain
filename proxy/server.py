import flask
import json
import IBPRE as pre
from flask import request


class Util:
    def __init__(self) -> None:
        self.proxy = pre.PreGA()
        (self.master_secret_key, self.params) = self.proxy.setup()

    def encrypt(self, id, msg):
        return self.serialize_ctext1(self.proxy.encrypt(self.params, id, msg))

    def reEncrypt(self, id, rk, cmsg):
        des_rk = self.deserialize_rk(rk)
        des_cmsg = self.deserialize_ctext1(cmsg)
        return self.serialize_ctext2(self.proxy.reEncrypt(self.params, id, des_rk, des_cmsg))

    def decrypt(self, sk2, id1, id2, cmsg):
        return self.proxy.decryptSecondLevel(self.params, self.deserialize_sk(sk2), id1, id2, self.deserialize_ctext2(cmsg))

    def deserialize_sk(self, data):
        return self.proxy.deserialize_sk(data)

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


server = flask.Flask(__name__)
util = Util()


@server.route('/encrypt', methods=['post'])
def encrypt():
    id = request.form['id']
    msg = request.form['msg']
    return util.encrypt(id, msg)


@server.route('/reEncrypt', methods=['post'])
def reEncrypt():
    id = request.form['id']
    rk = request.form['rk']
    cmsg = request.form['cmsg']
    return util.reEncrypt(id, rk, cmsg)


@server.route('/decrypt', methods=['post'])
def decrypt():
    sk2 = request.form['sk2']
    id1 = request.form['id1']
    id2 = request.form['id2']
    cmsg = request.form['cmsg']
    return util.decrypt(sk2, id1, id2, cmsg)


if __name__ == '__main__':
    server.run(debug=True, port=8888, host='0.0.0.0')
