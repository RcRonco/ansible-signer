from abc import ABC, abstractmethod

SIMPLE_FILTER = '^([a-zA-Z0-9]|-|_).*\.(yaml|yml|exe|python|ps1|json|conf|j2)+$'
DEFAULT_FILTER = '.*'


class Signer(ABC):
    @abstractmethod
    def sign(self, role_path, role_sign_path='', file_filter=DEFAULT_FILTER):
        pass


class Verifier(ABC):
    @abstractmethod
    def verify(self, role_path, role_sign_path=''):
        pass
