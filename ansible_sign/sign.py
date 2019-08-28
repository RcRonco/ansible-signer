import os
import re
import rsa
import yaml
import base64
import ansible_sign.helper as sign_helper


class AnsibleSigner:
    def __init__(self, private_key_path=""):
        priv_key = None
        
        # Load private key
        if os.path.exists(private_key_path):
            with open(private_key_path, 'rb') as pk_fd:
                priv_key = rsa.PrivateKey.load_pkcs1(pk_fd.read())
                
        # Generate new RSA key pair
        if priv_key is None:
            (self.pub_key, self.priv_key) = rsa.newkeys(2048)
        else:
            self.priv_key = priv_key

    def sign(self, role_path, role_sign_path='', file_filter=sign_helper.DEFAULT_FILTER):
        """
        Generate sign.yaml file for given role
        :param role_path: The role path
        :param role_sign_path: The sign.yaml location, Default - ${role_path}/sign.yaml
        :param file_filter: Regex to filter files, default will ignore hidden files (starting with .)
               will include only yaml,yml,json,exe,python,ps1,conf,j2 file extensions
        :return: Boolean - whether the sign process ended successfully
        """
        signed_files = {
            "files": {},
            "filter": file_filter
        }

        # Check private key is loaded
        if self.priv_key is None:
            print('Private key is not loaded')
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
        signed_data = yaml.safe_dump(signed_files,
                                     encoding='utf-8',
                                     allow_unicode=True,
                                     default_flow_style=False).decode('utf-8')

        # Sign the sign.yaml and insert it to him
        signed_files["sign.yaml"] = \
            base64.b64encode(self._sign_data(signed_data)).decode('utf-8')

        # Generate final sign.yaml
        signed_data = yaml.safe_dump(signed_files,
                                     encoding='utf-8',
                                     allow_unicode=True,
                                     default_flow_style=False).decode('utf-8')

        # Save to file
        with open(role_sign_path, 'w') as ofd:
            ofd.write(signed_data)
        return True

    def _sign_data(self, data="", hash_alg='SHA-256'):
        """
        Sign given string of data
        :param data: data to sign
        :param hash_alg: Hashing algorithm
        :return: Signature
        """
        encoded_data = data.encode()
        return rsa.sign(encoded_data, self.priv_key, hash_alg)

    def _sign_role(self,role_path, file_filter=sign_helper.DEFAULT_FILTER):
        """
        Scan role for files based on filter and sign all files
        :param role_path: Role location
        :param file_filter: Filter files by regex
        :return: Dict - Keys: files path
                        Values: files signature
        """
        role_signs = {}
        # Scan role folders
        for root, dirs, files in os.walk(role_path):
            for file in files:
                full_path = os.path.join(root, file)
                # Check if file name is matching the filter
                if not re.match(file_filter, file):
                    print('Skipping hidden file: {}'.format(full_path))
                    continue
                # Sign current file
                curr_sign = self._sign_data(open(full_path).read())
                role_signs[full_path] = base64.b64encode(curr_sign).decode('utf-8')
        return role_signs
