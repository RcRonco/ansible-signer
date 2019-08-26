# ansible-signer
An Extension to Ansible with the ability to sign and verify at playbook run roles integrity 

## Description
A tool to create a sign.yaml file which contains all the role related files and their RSA and SHA-256 signatures.  
#### sign.yaml structure
```yaml
filter: ^([a-zA-Z0-9]|-|_).*\.(yaml|yml|exe|python|ps1|json|conf|j2)+$
files:
  tasks/unit/install-modules.yml: PZ3XMEYg55POOYaC+lylTuofj2JvkRXJBxAm7+SXsaSb5Q2abUMqCnikTLvV4OsUU2cP+na5JwFE7O6kVE7fV2hZX+cN2ATx1JviEYUbThzSYJl9nH+yBYJeKAypNynfOU2KyuZ7g1sS1zPeeY65s7lgM6VPhlagjKVGrL6pyJ+9QJfxVNhEItDX5pFcKETUUGF+H9UmpVup0095sr9bYztvxq6oGVfznxG5eKPDMCPImil+/r9NovH615BA/Li9CRODkj4mLDAWu3GUWuPebPJ+KtpN0CehwYjFFvXQQ+Dg3jQpCWawsWyES3OeWdOXZ4f6QQsr/J4KaXdVevkknw==
  tasks/unit/install-unit.yml: LaOzLdyIMIUrbZVDMS1spzmxZCPXbY5lLzgMvuqAx4zJ6Vv6bhwa/ZM4Ltmu+O9/RBKmvkU3fjix+0QbPTG/Y84cAYFIYYePlVoCT1J/itCjXarWWVRgBAG2WQGtCny/oLgCG9bEkzLKmIgySPeDHYq0xp/rXJwmo6UXlkRirGNhzqapaEVY2lLD/jc60ccLecUf95IhpxZy9e7g0KZBF5W4aohl6rW4q66D9BWjgVEPzgsv4U7uu7aniHjV5lTwqOQ2PU0vTWscv2HgcLdG+6a4kIvzPvECDZ8xYt8350i9IgVaEL9BCe/G61U0mNePSG7r8EfAZ9VlcpwEiaIxZA==
  templates/stream/default.conf.j2: KnkNTtrMnpq3872IRwo2BNern2ZlibhtmDS6OK3yuV3bYSDxOv58wOn5i3WXuCkSy0EtIDseH8k4MkB1vp1wMQopVaVwISZ5XEN17Jbsmnpqd2KnvP4EVelrkgdWWEehoah9vX3WYSvCvh39wonMHBzj6uw7kwoaeC7O15wXNO1IeGIkSEeF5sKeCOFS1l2H65rVItZ+UMMZQMbtHvGlXMH9zyHz1+uXnxopYmurJiBReqmmVmseaCluijZm9m6nDA5FGj6zZE+a5+nZEIYhXMdAVWDSLnMLbN9tVM3NuUo/k5zYv/trSxpmm9S+8XIKacobu7lDtjmAdBUUNlhenQ==
  templates/www/index.html.j2: RN9bc4I+FS6zrwCoIrMXQv3b2a3zatSboHJiArwDhXcAPf6pspVe9+DVb5jGFx0KtMzf6/fzg1OL++aleGN4ICKs4UgrkxKQDMW3q/nu07IrFphBappMNMN5Zf3pQ+OOhtdGuvX2rejrYG61jIed714xxGdxaodKzxZiFh+acUipZ/bWaV6rtb+6+hNypK9BD4aRFJX0nGr9c+yKJqpG4OMyBoQWNdAOpHaFcGqjXrt5s5VUcdPik6Xil1ktQq6EHME901sCFcX81MXMG5wyh2Ne3OXvvI8vk8aLVYTp2bU7ZrfgD3Kv0wyexLC91xXLGOJgY9fIF51R5DGz9LoQ6w==
  vars/main.yml: aSCgTKd1Ug4CKC9HK6wUH5YogyyhFyMFUByhtPiy3Xbl9m382tbwbuw0DobzkdgWo5i6rvSre25ixE+3DN2DEYBUnVTS4rb9QA8IcXAE1uvBdAEBiSYknQc8ivyzgMLI1SU1drGHSgzKGxDILQy+HU8bFLK1dmdX5NHe1c99EyhWykircvt3ksZcA8/4FN37eLlcKW1NvJlaJHh8gMx9luouqdAEdRmUT9E3rOb/RBjuWVwQBE/9jkD0c8IDDxQ+nuUMkL/8QiOXNLf0bYLlPkpxtuBPaWrCYoDjF42S8M7Tne4hq/s3lYLSqZ+l+a19g/JIGXw+4eLeEezG9X4BxA==
  ....
  ....
  ....
sign.yaml: JncDteY/mvcOcHtIod6IzqXbMcrkxkl34A4Ciwn/ZkYvF+oPDIR+IrFaZ1USRO55RmLzcHjxdyhrBcPueFBDl2hszaRyr3eduBcmmTA2k3XScS6khy7F8rTYUjOtx8rS8oOciPjsaZghYSw8Aim1bm3Tb4NKRYR3BZvVKaAotwShCGiI2vl3jK2hug392qcKMXl/CmzoCq163XKQzB1m2pkQ7NCsVhv64AraA7CDCTvLip8ILCOQDQuEumq6aszZn+GZAvW3Qjy2GRJl6gRZkbFgLxj/n7EQdHLyVJ67/XYbhYEwbMq+HarapsGzJuEhDwzTHMrnADIOLnBLyTXKzw==
```

# Roadmap
- [X] Write AnsibleSigner
- [ ] Write AnsibleVerifier
- [ ] Extend Ansible's ansible-playbook cli to check roles before running plays
