
# PyPoa (Padding Oracle Attack)

A python implementation of the Padding Oracle Attack.

## Features

* Decrypts and encrypts messages
* Allows you to implement your own oracle padding validation

## Installing / Getting started

```shell
git clone https://github.com/Dukezo/pypoa.git
pip install .
```

Clone the repository, install the package and you are ready to go.

## Example usage

Decrypting ciphertexts:
```python
class MyOracle(pypoa.Oracle):
    def validate(self, payload):
        proc = subprocess.Popen("echo %s | nc example.com 12345" % payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output = str(proc.communicate()[0])
        return "invalid padding" not in output

ciphertext = "2495de02c6af8378db81b410c54cc3f75da4c0d4122d1c597496dd5b00038a32a333bcbabe327bd8292ca295fc8003463fe4c235a502d994d85a1332890ee080b8fd160937f260aa5449b2e05e8464cf" 
IV = binascii.hexlify(b"This is an IV456").decode("ascii")  
plaintext = pypoa.decrypt(ciphertext, 16, MyOracle(), IV)
```

Encrypting plaintexts:
```python
class MyOracle(pypoa.Oracle):
    def validate(self, payload):
        proc = subprocess.Popen("echo %s | nc example.com 12345" % payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output = str(proc.communicate()[0])
        return "invalid padding" not in output

plaintext = 'Top secret message'
ciphertext = pypoa.encrypt(plaintext, 16, MyOracle())
```

## Licensing

See the LICENSE file for license rights and limitations (MIT).