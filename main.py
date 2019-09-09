#from ansible_sign.sign import AnsibleSigner

#signer = AnsibleSigner('key.pem')
#signer.sign('./nginx-role')

from ansible_sign.rsa_verifier import RSAVerifier
verifier = RSAVerifier('public.pem')
verifier.verify('./nginx-role')