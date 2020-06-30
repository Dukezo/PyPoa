import unittest
from unittest.mock import patch
import pypoa

class TestPypoa(unittest.TestCase):

    def test_Oracle(self):
        self.assertRaises(NotImplementedError, pypoa.Oracle().validate, "")

    def test_pad(self):
        self.assertEqual(len(pypoa.pad("This is an unit test", 16)) % 16, 0)
        self.assertEqual(len(pypoa.pad("This is an unit test", 20)) % 20, 0)

    def test_unpad(self):
        msg = "This is an unit test"
        padded = pypoa.pad(msg, 16)
        unpadded = pypoa.unpad(padded)
        self.assertEqual(len(unpadded), len(msg))

    @patch("pypoa.Oracle")
    def test_decrypt(self, mock_oracle):
        mock_oracle.validate.return_value = False
        self.assertRaises(pypoa.PaddingDeterminationError, pypoa.decrypt, "3D3D3D3D3D3D3D3D", 4, mock_oracle, verbose=False)

        mock_oracle.validate.return_value = True
        self.assertRaises(pypoa.InvalidBlockSizeError, pypoa.decrypt, "3D3D3D3D3D3D3D3D3D3D", 4, mock_oracle, verbose=False)
        self.assertRaises(ValueError, pypoa.decrypt, "3D3D3D3D3D3D3D3D", 8, mock_oracle, verbose=False)
        self.assertEqual(len(pypoa.decrypt("3D3D3D3D3D3D3D3D", 4, mock_oracle, verbose=False)), 4)

    @patch("pypoa.Oracle")
    def test_encrypt(self, mock_oracle):
        mock_oracle.validate.return_value = False
        self.assertRaises(pypoa.PaddingDeterminationError, pypoa.encrypt, "This is an unit test", 16, mock_oracle, verbose=False)

        mock_oracle.validate.return_value = True
        self.assertEqual(len(pypoa.encrypt("This is an unit test", 4, mock_oracle, verbose=False)), 56) # len(plaintext) + len(padding) + len(IV)

if __name__ == "__main__":
    unittest.main()