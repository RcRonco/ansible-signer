import os
import hvac
import yaml
import base64
from ansible_sign.ansible_sign import Verifier
from ansible_sign.vault_signer import VaultSigner


class VaultVerifier(Verifier):
    def __init__(self, address: str, token: str, key_name: str, mount_path: str = 'transit', verify: bool = True):
        self.vault_addr = address
        self.token = token
        self.transit_key = key_name
        self.verify = verify
        self.transit_mount = mount_path
        self.client = hvac.Client(self.vault_addr, self.token, verify=self.verify)

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
        if not self.client.is_authenticated():
            print('Failed to authenticate to vault server')
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

        # Load sign yaml and verify backend
        signed_files = yaml.load(open(role_sign_path).read())
        if signed_files["sign_backend"] != VaultSigner.get_name():
            return False, ['sign.yaml']

        # Verify sign.yaml signature
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
            "sign_backend": signed_file["sign_backend"],
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
