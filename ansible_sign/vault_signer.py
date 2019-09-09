import os
import hvac
import yaml
import base64
from ansible_sign.ansible_sign import Signer, DEFAULT_FILTER
from ansible_sign.role_scanner import RoleScanner


class VaultSigner(Signer):
    def __init__(self, address: str, token: str, key_name: str, mount_path: str = 'transit', verify: bool = True):
        self.vault_addr = address
        self.token = token
        self.transit_key = key_name
        self.verify = verify
        self.transit_mount = mount_path
        self.client = hvac.Client(self.vault_addr, self.token, verify=self.verify)

    @staticmethod
    def get_name():
        return "VaultSigner"

    def sign(self, role_path: str, role_sign_path: str = '', file_filter: str = DEFAULT_FILTER) -> bool:
        """
        Generate sign.yaml file for given role
        :param role_path: The role path
        :param role_sign_path: The sign.yaml location, Default - ${role_path}/sign.yaml
        :param file_filter: Regex to filter files, default will ignore hidden files (starting with .)
               will include only yaml,yml,json,exe,python,ps1,conf,j2 file extensions
        :return: Boolean - whether the sign process ended successfully
        """
        signed_files = {
            "sign_backend": self.get_name(),
            "files": {},
            "filter": file_filter
        }

        # Check private key is loaded
        if not self.client.is_authenticated():
            print('Failed to authenticate to vault server')
            return False

        # Check role exists and is directory
        if not os.path.exists(role_path) or not os.path.isdir(role_path):
            print('Given role path is missing or not a directory')
            return False

        if role_sign_path == '':
            role_sign_path = os.path.join(role_path, 'sign.yaml')

        # Create sign for the role
        signed_files["files"] = self._sign_role(role_path, file_filter)

        # Generate the sign data
        signed_data = base64.b64encode(
            yaml.safe_dump(
                signed_files,
                encoding='utf-8',
                allow_unicode=True,
                default_flow_style=False
            )
        )

        # Sign the sign.yaml and insert it to him
        signed_files["sign.yaml"] = self._sign_data(signed_data)

        # Generate final sign.yaml
        signed_data = yaml.safe_dump(signed_files,
                                     encoding='utf-8',
                                     allow_unicode=True,
                                     default_flow_style=False).decode('utf-8')

        # Save to file
        with open(role_sign_path, 'w') as ofd:
            ofd.write(signed_data)
        return True

    def _sign_data(self, data: bytes = "", hash_alg: str = 'SHA-256') -> str:
        """
        Sign given string of data
        :param data: base64 data to sign
        :param hash_alg: Hashing algorithm
        :return: Signature
        """
        sign_data_response = self.client.transit_sign_data(
            self.transit_key,
            data,
            hash_algorithm=hash_alg,
            mount_point=self.transit_mount
        )
        return sign_data_response['data']['signature']

    def _sign_role(self, role_path: str, file_filter: str = DEFAULT_FILTER) -> dict:
        """
        Scan role for files based on filter and sign all files
        :param role_path: Role location
        :param file_filter: Filter files by regex
        :return: Dict - Keys: files path
                        Values: files signature
        """
        role_signs = {}
        scanner = RoleScanner(file_filter)
        for f in scanner.get_files(role_path):
            role_signs[f] = self._sign_data(base64.b64encode(open(f).read()))

        return role_signs
