import rsa
import base64
def generate_key():
    """
    生成公私钥文件
    :return:
    """
    (public_key, private_key) = rsa.newkeys(512, poolsize=8)

    with open('public.pem', 'w+') as f:
        f.write(public_key.save_pkcs1().decode())

    with open('private.pem', 'w+') as f:
        f.write(private_key.save_pkcs1().decode())


def sign(source_file = 'secret.txt', pri_key = 'private.pem'):
    """
    rsa签名算法
    :return: filesign base64转码后的签名
    """
    with open(pri_key, 'r') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read().encode())
        # print(privkey)

    with open(source_file,'rb') as f:
        file_sign = rsa.sign(f, privkey,'SHA-256')

    return base64.b64encode(file_sign)

def verify(file_sign, source_file = 'secret.txt', pub_key = 'public.pem'):
    """
    验签
    :return: bool 验签是否成功
    """
    with open(pub_key, 'r') as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read().encode())
        # print(pubkey)

    with open(source_file, 'rb') as f:
        assert rsa.verify(f, base64.b64decode(file_sign), pubkey)

    return 'verify ok!'


def main():
    generate_key()

    file_sign = sign()
    print(file_sign)

    file_verify = verify(file_sign)
    print(file_verify)
    # print(file_sign)

if __name__ =="__main__":
    main()