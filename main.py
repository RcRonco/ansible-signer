#from ansible_sign.sign import AnsibleSigner

#signer = AnsibleSigner('key.pem')
#signer.sign('./nginx-role')

from ansible_sign.verify import AnsibleSignVerifier
verifier = AnsibleSignVerifier('public.pem')
verifier.verify('./nginx-role')