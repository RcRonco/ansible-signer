from abc import ABC, abstractmethod

DEFAULT_FILTER = '^([a-zA-Z0-9]|-|_).*\.(yaml|yml|exe|python|ps1|json|conf|j2)+$'


class Signer(ABC):
    @abstractmethod
    def sign(self, role_path, role_sign_path='', file_filter=DEFAULT_FILTER):
        pass


class Verifier(ABC):
    @abstractmethod
    def verify(self, role_path, role_sign_path=''):
        pass