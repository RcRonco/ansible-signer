import os
import rsa
import yaml
import base64
from ansible_sign.ansible_sign import Verifier


class AnsibleSignVerifier(Verifier):
    def __init__(self, public_key_path=""):
        self.pub_key = None
        # Load public key
        if os.path.exists(public_key_path):
            with open(public_key_path, 'rb') as pk_fd:
                self.pub_key = rsa.PublicKey.load_pkcs1_openssl_pem(pk_fd.read())

    def verify(self, role_path, role_sign_path=''):
        """
        Verify sign.yaml file for given role
        :param role_path: The role path
        :param role_sign_path: The sign.yaml location, Default - ${role_path}/sign.yaml
        :return: Boolean - whether the sign is valid
                 string[] - files which the sign is invalid for them, if role is valid the value should be empty array.
        """
        invalid_files = []
        # Check Public key is loaded
        if self.pub_key is None:
            print('Public key is not loaded')
            return False, invalid_files

        # Check that the role exists and is directory
        if not os.path.exists(role_path) or not os.path.isdir(role_path):
            print('Given role path is missing or not a directory')
            return False, invalid_files

        # Check the role sign exists
        if role_sign_path == '':
            role_sign_path = os.path.join(role_path, 'sign.yaml')
        if not os.path.exists(role_path):
            return False, ['sign.yaml']

        # Verify sign.yaml signature
        signed_files = yaml.load(open(role_sign_path).read())
        if not self._verify_sign_file_sig(signed_files):
            return False, ['sign.yaml']

        # Verify all role files
        for file, sign in signed_files["files"].items():
            if not self._verify_file_sig(file, base64.b64decode(sign)):
                invalid_files.append(file)

        return True, invalid_files

    def _verify_file_sig(self, file_path, sign):
        """
        Verify signature for file
        :param file_path: path for the file
        :param sign: file signature
        :return: Boolean - whether the sign is valid
        """
        with open(file_path) as fd:
            try:
                rsa.verify(fd.read().encode(), sign, self.pub_key)
                return True
            except rsa.VerificationError as verr:
                print(verr)
                return False

    def _verify_sign_file_sig(self, signed_file):
        """
        Verify signature for sign.yaml file
        :param signed_file: sign.yaml path
        :return: Boolean - whether the sign is valid
        """
        # Build original sign.yaml without sign.yaml signature
        signless_sign_yaml = {
            "files": signed_file["files"],
            "filter": signed_file["filter"]
        }
        signed_data = yaml.safe_dump(signless_sign_yaml,
                                     encoding='utf-8',
                                     allow_unicode=True,
                                     default_flow_style=False).decode('utf-8')
        # Extract signature for sign.yaml
        sign = base64.b64decode(signed_file["sign.yaml"])
        try:
            rsa.verify(signed_data.encode(), sign, self.pub_key)
            return True
        except rsa.VerificationError as verr:
            print(verr)
            return False
