import random
import hashlib
from typing import Any, Tuple
from .base_algorithm import BaseCryptoAlgorithm


class RsaCipher(BaseCryptoAlgorithm):
    """
    Implementacja RSA z proper sign/verify i bezpieczeństwem.
    
    - Szyfrowanie: M ^ e mod n (textbook RSA)
    - Podpis: SHA256(M) ^ d mod n
    - Weryfikacja: SHA256(M) ^ e mod n == oryg. hash
    
    WAŻNE: To jest textbook RSA. Dla produkcji użyj bibliotek takich jak PyCryptodome
    z OAEP padding-em i PSS podpisem!
    """
    
    def __init__(self):
        super().__init__("RSA", "Asymmetric encryption using public and private keys.")
        self.hash_func = hashlib.sha256

    def validate_key(self, key: Any) -> bool:
        """Dla RSA klucze są krotkami (e, n) i (d, n)."""
        return isinstance(key, tuple) and len(key) == 2

    def generate_keys(self, bit_length: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Generuje parę kluczy RSA (public_key, private_key).
        
        Args:
            bit_length: Długość bitowa n (domyślnie 1024; dla produkcji użyj >= 2048)
        
        Returns:
            Tuple: ((e, n), (d, n)) gdzie e, d, n to liczby całkowite
        """
        # Generuj dwie duże liczby pierwsze
        p = self._generate_prime(bit_length // 2)
        q = self._generate_prime(bit_length // 2)
        
        # Oblicz n = p * q
        n = p * q
        
        # Oblicz φ(n) = (p-1)(q-1)
        phi = (p - 1) * (q - 1)

        # Wybierz e (zazwyczaj 65537, musi być coprime z φ(n))
        e = 65537
        while self._gcd(e, phi) != 1:
            e = random.randrange(3, phi, 2)

        # Oblicz d (Private exponent) — modular inverse e mod φ(n)
        d = self._mod_inverse(e, phi)
        
        return (e, n), (d, n)

    def encrypt(self, data: Any, public_key: Tuple[int, int]) -> bytes:
        """
        Szyfruje dane przy użyciu klucza publicznego.
        
        Implementacja: Każdy fragment (poza ostatnim) zawiera dane + length-prefix ostatniego fragmentu.
        
        Args:
            data: str lub bytes do zaszyfrowania
            public_key: (e, n) — klucz publiczny
        
        Returns:
            bytes: Zaszyfrowane dane (binary format)
        """
        e, n = public_key
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Rozmiar fragmentu: (n.bit_length() - 1) // 8 bajtów
        # Upewniamy się, że m < n
        chunk_size = (n.bit_length() - 1) // 8
        if chunk_size <= 2:
            raise ValueError("Klucz RSA jest za mały")
        
        # Przygotuj dane z length-prefix
        # Format: [2 bajty - długość oryginalnych danych] + [dane]
        length_bytes = len(data).to_bytes(2, 'big')
        padded_data = length_bytes + data
        
        encrypted_chunks = []
        
        # Szyfruj każdy fragment
        for i in range(0, len(padded_data), chunk_size):
            chunk = padded_data[i:i + chunk_size]
            
            # Jeśli ostatni fragment jest krótszy, dodaj padding null bytes
            if len(chunk) < chunk_size:
                chunk = chunk + b'\x00' * (chunk_size - len(chunk))
            
            # Konwertuj chunk na liczbę
            m = int.from_bytes(chunk, 'big')
            
            # Szyfruj: c = m^e mod n
            c = pow(m, e, n)
            
            # Konwertuj wynik na bajty (z paddingiem do pełnego rozmiaru)
            encrypted_bytes = c.to_bytes((n.bit_length() + 7) // 8, 'big')
            encrypted_chunks.append(encrypted_bytes)
        
        return b''.join(encrypted_chunks)

    def decrypt(self, encrypted_data: bytes, private_key: Tuple[int, int]) -> bytes:
        """
        Deszyfruje dane przy użyciu klucza prywatnego.
        
        Odczytuje length-prefix do ustalenia rozmiaru oryginalnych danych.
        
        Args:
            encrypted_data: bytes — zaszyfrowane dane (output z encrypt())
            private_key: (d, n) — klucz prywatny
        
        Returns:
            bytes: Odszyfrowane oryginalne dane
        """
        d, n = private_key
        
        # Rozmiar fragmentu dla deszyfrowania musi pasować do rozmiaru z szyfrowania
        # Każdy fragment zaszyfrowany = (n.bit_length() + 7) // 8 bajtów
        chunk_size = (n.bit_length() + 7) // 8
        decrypted_chunks = []
        
        for i in range(0, len(encrypted_data), chunk_size):
            chunk = encrypted_data[i:i + chunk_size]
            
            # Konwertuj chunk na liczbę
            c = int.from_bytes(chunk, 'big')
            
            # Deszyfruj: m = c^d mod n
            m = pow(c, d, n)
            
            # Konwertuj wynik na bajty (rozmiar = chunk_size - 1, by m < n)
            decrypted_bytes = m.to_bytes((n.bit_length() - 1) // 8, 'big')
            decrypted_chunks.append(decrypted_bytes)
        
        # Łącz fragmenty
        padded_result = b''.join(decrypted_chunks)
        
        # Odczytaj length-prefix (pierwsze 2 bajty)
        if len(padded_result) < 2:
            raise ValueError("Deszyfrowane dane są za krótkie")
        
        data_length = int.from_bytes(padded_result[:2], 'big')
        
        # Zwróć tylko oryginalną długość danych (bez length-prefix)
        actual_data = padded_result[2:2 + data_length]
        
        return actual_data

    def sign(self, data: bytes, private_key: Tuple[int, int]) -> bytes:
        """
        Tworzy podpis cyfrowy dla danych przy użyciu klucza prywatnego.
        
        Proces:
        1. Hash(data) = SHA256(data)
        2. signature = Hash ^ d mod n
        
        Args:
            data: bytes — dane do podpisania
            private_key: (d, n) — klucz prywatny
        
        Returns:
            bytes: Podpis (binary format)
        """
        d, n = private_key
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # 1. Oblicz hash danych
        data_hash = self.hash_func(data).digest()
        
        # 2. Konwertuj hash na liczbę
        h = int.from_bytes(data_hash, 'big')
        
        # 3. Podpisz: s = h^d mod n
        signature = pow(h, d, n)
        
        # 4. Konwertuj podpis na bajty
        signature_bytes = signature.to_bytes((n.bit_length() + 7) // 8, 'big')
        
        return signature_bytes

    def verify(self, data: bytes, signature: bytes, public_key: Tuple[int, int]) -> bool:
        """
        Weryfikuje podpis cyfrowy dla danych przy użyciu klucza publicznego.
        
        Proces:
        1. Hash(data) = SHA256(data)
        2. verified_hash = signature ^ e mod n
        3. Zwróć (verified_hash == Hash)
        
        Args:
            data: bytes — oryginalne dane
            signature: bytes — podpis do weryfikacji
            public_key: (e, n) — klucz publiczny
        
        Returns:
            bool: True jeśli podpis jest prawidłowy, False w przeciwnym razie
        """
        e, n = public_key
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            # 1. Oblicz hash oryg. danych
            data_hash = self.hash_func(data).digest()
            h = int.from_bytes(data_hash, 'big')
            
            # 2. Weryfikuj podpis: v = s^e mod n
            s = int.from_bytes(signature, 'big')
            verified_hash = pow(s, e, n)
            
            # 3. Porównaj hashe
            return verified_hash == h
        except Exception:
            return False

    # --- Pomocnicze metody ---

    def _is_prime(self, n: int, k: int = 5) -> bool:
        """Miller-Rabin test na prymalność."""
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
        
        # Rozkład n-1 = 2^r * s
        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2
        
        # Test Miller-Rabin
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

    def _generate_prime(self, bit_length: int) -> int:
        """Generuje losową liczbę pierwszą o zadanej długości bitowej."""
        while True:
            p = random.getrandbits(bit_length)
            # Ustaw MSB i LSB na 1
            p |= (1 << (bit_length - 1)) | 1
            if self._is_prime(p):
                return p

    @staticmethod
    def _gcd(a: int, b: int) -> int:
        """Oblicza GCD(a, b) algorytmem Euklidesa."""
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def _mod_inverse(a: int, m: int) -> int:
        """
        Oblicza modular inverse a mod m za pomocą extended Euclidean algorithm.
        
        Zwraca x takie, że (a * x) mod m = 1.
        """
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        if x1 < 0:
            x1 += m0
        return x1
