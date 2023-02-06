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

    def rkGen(self, sk1, id1, id2):
        return self.serialize_rk(self.proxy.rkGen(self.params, self.deserialize_sk(sk1), id1, id2))

    def serialize_sk(self, data):
        return self.proxy.serialize_sk(data)

    def deserialize_sk(self, data):
        return self.proxy.deserialize_sk(data)

    def serialize_rk(self, data):
        return self.proxy.serialize_rk(data)

    def deserialize_rk(self, data):
        return self.proxy.deserialize_rk(data)


# 创建一个服务，把当前这个python文件当做一个服务
server = flask.Flask(__name__)
util = Util()


@server.route('/keyGen', methods=['post'])
def keyGen():
    id = request.form['id']
    return json.dumps(util.keyGen(id), ensure_ascii=False)


@server.route('/rkGen', methods=['post'])
def rkGen():
    sk1 = eval(request.form['sk1'])
    id1 = request.form['id1']
    id2 = request.form['id2']
    return json.dumps(util.rkGen(sk1, id1, id2), ensure_ascii=False)


if __name__ == '__main__':
    # 指定端口,host,0.0.0.0代表不管几个网卡，任何ip都可访问
    server.run(debug=True, port=1234, host='0.0.0.0')
