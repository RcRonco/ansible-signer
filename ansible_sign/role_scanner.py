import os
import re
from ansible_sign.ansible_sign import DEFAULT_FILTER


class RoleScanner:
    def __init__(self, file_filter=DEFAULT_FILTER):
        self.filter = file_filter

    def get_files(self, role_path, file_filter=None):
        role_files = []
        if file_filter is None:
            file_filter = self.filter

        for root, dirs, files in os.walk(role_path):
            for file in files:
                full_path = os.path.join(root, file)
                # Check if file name is matching the filter
                if not re.match(file_filter, file):
                    print('Skipping hidden file: {}'.format(full_path))
                    continue
                # Sign current file
                role_files.append(full_path)
        return role_files