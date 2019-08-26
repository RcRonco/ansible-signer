from ansible_sign.sign import AnsibleSigner

signer = AnsibleSigner()
signer.gen_ansible_role_sign('./nginx-role')