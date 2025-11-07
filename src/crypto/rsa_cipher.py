import random
from typing import Any
from .base_algorithm import BaseCryptoAlgorithm

class RsaCipher(BaseCryptoAlgorithm):
    def __init__(self):
        super().__init__("RSA", "Asymmetric encryption using public and private keys.")

    def validate_key(self, key: Any) -> bool:
        # Dla RSA klucze są krotkami (e, n) i (d, n).
        # Walidacja jest niejawna podczas operacji szyfrowania/deszyfrowania.
        # Zwracamy True, aby umożliwić działanie, błędy zostaną przechwycone później.
        return True

    def generate_keys(self, bit_length=1024):
        p = self._generate_prime(bit_length // 2)
        q = self._generate_prime(bit_length // 2)
        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        while self._gcd(e, phi) != 1:
            e = random.randrange(3, phi, 2)

        d = self._mod_inverse(e, phi)
        return (e, n), (d, n)

    def encrypt(self, data, public_key):
        e, n = public_key
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        chunk_size = (n.bit_length() - 1) // 8
        encrypted_chunks = []

        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            m = int.from_bytes(chunk, 'big')
            c = pow(m, e, n)
            encrypted_chunks.append(c.to_bytes((n.bit_length() + 7) // 8, 'big'))
        
        return b''.join(encrypted_chunks)

    def decrypt(self, encrypted_data, private_key):
        d, n = private_key
        
        chunk_size = (n.bit_length() + 7) // 8
        decrypted_chunks = []

        for i in range(0, len(encrypted_data), chunk_size):
            chunk = encrypted_data[i:i+chunk_size]
            c = int.from_bytes(chunk, 'big')
            m = pow(c, d, n)
            decrypted_chunks.append(m.to_bytes((n.bit_length() - 1) // 8, 'big'))
        
        return b''.join(decrypted_chunks).rstrip(b'\x00')

    def _is_prime(self, n, k=5):
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
        
        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2
        
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def _generate_prime(self, bit_length):
        while True:
            p = random.getrandbits(bit_length)
            p |= (1 << bit_length - 1) | 1
            if self._is_prime(p):
                return p

    def _gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def _mod_inverse(self, a, m):
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        if x1 < 0:
            x1 += m0
        return x1
