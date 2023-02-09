package main

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"

	"github.com/fernet/fernet-go"
)

type CompoundKey struct {
	Key      string
	Location string
}

func encodeCompoundKey(ckey *CompoundKey) string {
	res, err := json.Marshal(ckey)
	if err != nil {
		panic(err)
	}
	return string(res)
}

func decodeCompoundKey(data string) CompoundKey {
	var res CompoundKey
	err := json.Unmarshal([]byte(data), &res)
	if err != nil {
		panic(err)
	}
	return res
}

func writeSecretKey(sk, id string) {
	filePath := "./secret_key_" + id
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	write.WriteString(sk)
	write.Flush()
}

func generateEncryptKey() string {
	k := fernet.MustDecodeKeys("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=")
	err := k[0].Generate()
	if err != nil {
		panic(err)
	}
	return k[0].Encode()
}

func encryptUserData(key, msg string) string {
	k := fernet.MustDecodeKeys(key)
	tok, err := fernet.EncryptAndSign([]byte(msg), k[0])
	if err != nil {
		panic(err)
	}
	return string(tok)
}

func decryptUserData(msg, key string) string {
	k := fernet.MustDecodeKeys(key)
	return string(fernet.VerifyAndDecrypt([]byte(msg), 2*time.Second, k))
}

func getSecretKey(id string) string {
	file, err := os.OpenFile("./secret_key_"+id, os.O_RDONLY, 0666)
	if err == nil {
		sk, err := ioutil.ReadAll(file)
		if err != nil {
			panic(err)
		}
		return string(sk)
	}
	urlValues := url.Values{}
	urlValues.Add("id", id)
	resp, err := http.PostForm("http://127.0.0.1:1234/keyGen", urlValues)
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	sk := string(body)
	writeSecretKey(sk, id)
	return sk
}

// 请求proxy用自己的id把对称密钥加密，得到的数据上传cloud
func encrypt(id, msg string) string {
	urlValues := url.Values{}
	urlValues.Add("id", id)
	urlValues.Add("msg", msg)
	resp, err := http.PostForm("http://127.0.0.1:8888/encrypt", urlValues)
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return string(body)
}

func rkGenRemote(sk1, id1, id2 string) string {
	urlValues := url.Values{}
	urlValues.Add("id1", id1)
	urlValues.Add("id2", id2)
	urlValues.Add("sk1", sk1)
	resp, err := http.PostForm("http://127.0.0.1:8888/rkGen", urlValues)
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return string(body)
}

func rkGen(sk1, id1, id2 string) string {
	out, err := exec.Command("python3", "crypto.py", "rkGen", sk1, id1, id2).Output()
	if err != nil {
		panic(err)
	}
	return string(out)
}

// 从cloud获取一阶加密的对称密钥后，请求proxy用rk进行二次加密，后续发送方把二次加密
// 的结果发送给对方
func reEncrypt(id, rk, cmsg string) string {
	urlValues := url.Values{}
	urlValues.Add("id", id)
	urlValues.Add("rk", rk)
	urlValues.Add("cmsg", cmsg)
	resp, err := http.PostForm("http://127.0.0.1:8888/reEncrypt", urlValues)
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return string(body)
}

// 数据请求方得到二次加密的结果后，用自己的私钥进行解密，最终得到
// 对称密钥
func decrypt(sk2, id1, id2, cmsg string) string {
	out, err := exec.Command("python3", "crypto.py", "decrypt", sk2, id1, id2, cmsg).Output()
	if err != nil {
		panic(err)
	}
	return string(out)
}

func main() {
	A, B := "alice", "bob"
	cpkey := CompoundKey{Key: generateEncryptKey(), Location: "/alice/hello.txt"}
	final := encryptUserData(cpkey.Key, "world")
	sk1 := getSecretKey(A)
	sk2 := getSecretKey(B)

	ckey := encrypt(A, encodeCompoundKey(&cpkey))

	rk := rkGen(sk1, A, B)

	re_ckey := reEncrypt(A, rk, ckey)

	de_key := decrypt(sk2, A, B, re_ckey)

	// fmt.Println(de_key)

	println(decryptUserData(final, decodeCompoundKey(de_key).Key))
}
