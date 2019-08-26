import os
import re
import rsa
import yaml
import base64

DEFAULT_FILTER = '^([a-zA-Z0-9]|-|_).*\.(yaml|yml|exe|python|ps1|json|conf|j2)+$'


class AnsibleSigner:
    def __init__(self, private_key_path="", public_key_path=""):
        pub_key = None
        priv_key = None
        if os.path.exists(private_key_path):
            with open(private_key_path, 'rb') as pk_fd:
                priv_key = rsa.PrivateKey.load_pkcs1(pk_fd.read())
        if os.path.exists(public_key_path):
            with open(public_key_path, 'rb') as pk_fd:
                pub_key = rsa.PublicKey.load_pkcs1(pk_fd.read())
        if priv_key is None or pub_key is None:
            (self.pub_key, self.priv_key) = rsa.newkeys(2048)
        else:
            self.pub_key = pub_key
            self.priv_key = priv_key

    def sign_data(self, data="", hash_alg='SHA-256'):
        encoded_data = data.encode()
        return rsa.sign(encoded_data, self.priv_key, hash_alg)

    def gen_ansible_role_sign(self, role_path, role_sign_path='', filter=DEFAULT_FILTER):
        signed_files = {"files": {}}
        if role_sign_path == '':
            role_sign_path = os.path.join(role_path, 'sign.yaml')
        for root, dirs, files in os.walk(role_path):
            for file in files:
                full_path = os.path.join(root, file)
                if not re.match(filter, file):
                    print('Skipping hidden file: {}'.format(full_path))
                    continue
                signed_files["files"][full_path] = \
                    base64.b64encode(self.sign_data(open(full_path).read())).decode('utf-8')
        signed_data = yaml.safe_dump(signed_files,
                                     encoding='utf-8',
                                     allow_unicode=True,
                                     default_flow_style=False).decode('utf-8')
        signed_files["sign.yaml"] = \
            base64.b64encode(self.sign_data(signed_data)).decode('utf-8')
        signed_data = yaml.safe_dump(signed_files,
                                     encoding='utf-8',
                                     allow_unicode=True,
                                     default_flow_style=False).decode('utf-8')
        with open(role_sign_path, 'w') as ofd:
            ofd.write(signed_data)