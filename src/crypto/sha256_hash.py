from typing import Any
from .base_algorithm import BaseCryptoAlgorithm


class SHA256Hash(BaseCryptoAlgorithm):
    """
    SHA-256 - kryptograficzna funkcja skrótu
    Tworzy 256-bitowy (32 bajtowy) skrót z dowolnych danych
    """
    
    def __init__(self):
        super().__init__(
            name="SHA-256",
            description="Kryptograficzna funkcja skrótu SHA-256 (256 bitów = 32 bajty). Zwraca 64-znakowy heks skrótu."
        )
    
    def encrypt(self, data: str, key: Any = None) -> str:
        """
        Oblicza SHA-256 skrót tekstu
        (SHA-256 nie używa klucza - jest to funkcja skrótu, nie szyfrowania)
        
        Parametry:
        - data: str - tekst do zhaszowania
        - key: Any - ignorowany (SHA-256 nie używa klucza)
        
        Zwraca: str - 64-znakowy heks skrótu (256 bitów = 32 bajty)
        """
        message_bytes = data.encode('utf-8')
        hash_digest = self.sha256(message_bytes)
        return hash_digest.hex()
    
    def decrypt(self, data: str, key: Any = None) -> str:
        """
        SHA-256 jest funkcją skrótu - nie można jej odwrócić
        Ta metoda zwraca informację że SHA-256 nie jest odwracalne
        """
        raise NotImplementedError(
            "SHA-256 jest funkcją skrótu (hash), nie szyfrem. "
            "Nie można odwrócić skrótu aby uzyskać oryginalną wiadomość. "
            "SHA-256 można jedynie: 1) obliczyć skrót (encrypt), 2) sprawdzić czy skróty są identyczne"
        )
    
    def validate_key(self, key: Any) -> bool:
        """SHA-256 nie wymaga klucza - zawsze zwraca True"""
        return True
    
    @staticmethod
    def sha256(data: bytes) -> bytes:
        """
        Implementacja SHA-256 od zera
        
        Parametry:
        - data: bytes - dane do zhaszowania
        
        Zwraca: bytes - 32 bajty (256 bitów) skrótu
        """
        # Stałe K (pierwsze 32 bity pierwiastka kwad. 64 liczb pierwszych)
        K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        
        # Początkowe wartości H (pierwsze 32 bity pierwiastka kwad. pierwszych 8 liczb pierwszych)
        h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
        h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        
        # Pre-processing: padding
        msg_len = len(data)
        msg_bits = msg_len * 8
        padded = bytearray(data)
        padded.append(0x80)
        
        while (len(padded) % 64) != 56:
            padded.append(0x00)
        
        padded += msg_bits.to_bytes(8, byteorder='big')
        
        # Przetwarzaj każdy 512-bitowy blok
        for chunk_start in range(0, len(padded), 64):
            chunk = padded[chunk_start:chunk_start + 64]
            
            # Podziel na 16 słów (32-bitowych)
            w = []
            for i in range(16):
                word = int.from_bytes(chunk[i*4:(i+1)*4], byteorder='big')
                w.append(word)
            
            # Rozszerz na 64 słowa
            for i in range(16, 64):
                s0 = SHA256Hash._rightrotate(w[i-15], 7) ^ SHA256Hash._rightrotate(w[i-15], 18) ^ (w[i-15] >> 3)
                s1 = SHA256Hash._rightrotate(w[i-2], 17) ^ SHA256Hash._rightrotate(w[i-2], 19) ^ (w[i-2] >> 10)
                w.append((w[i-16] + s0 + w[i-7] + s1) & 0xffffffff)
            
            # Zmienne robocze
            a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
            
            # Główna pętla kompresu (64 iteracje)
            for i in range(64):
                S1 = SHA256Hash._rightrotate(e, 6) ^ SHA256Hash._rightrotate(e, 11) ^ SHA256Hash._rightrotate(e, 25)
                ch = (e & f) ^ ((~e) & g)
                temp1 = (h + S1 + ch + K[i] + w[i]) & 0xffffffff
                S0 = SHA256Hash._rightrotate(a, 2) ^ SHA256Hash._rightrotate(a, 13) ^ SHA256Hash._rightrotate(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (S0 + maj) & 0xffffffff
                
                h, g, f = g, f, e
                e = (d + temp1) & 0xffffffff
                d, c, b, a = c, b, a, (temp1 + temp2) & 0xffffffff
            
            # Dodaj do wartości skrótu
            h0 = (h0 + a) & 0xffffffff
            h1 = (h1 + b) & 0xffffffff
            h2 = (h2 + c) & 0xffffffff
            h3 = (h3 + d) & 0xffffffff
            h4 = (h4 + e) & 0xffffffff
            h5 = (h5 + f) & 0xffffffff
            h6 = (h6 + g) & 0xffffffff
            h7 = (h7 + h) & 0xffffffff
        
        # Skrót końcowy - połącz 8 32-bitowych słów
        hash_bytes = b''
        for h_val in [h0, h1, h2, h3, h4, h5, h6, h7]:
            hash_bytes += h_val.to_bytes(4, byteorder='big')
        
        return hash_bytes
    
    @staticmethod
    def _rightrotate(n: int, d: int) -> int:
        """
        Obrót w prawo (right rotate) dla 32-bitowej liczby
        
        Parametry:
        - n: liczba do obrócenia
        - d: liczba bitów do obrócenia
        
        Zwraca: obrocona liczba
        """
        return ((n >> d) | (n << (32 - d))) & 0xffffffff


# Funkcje pomocnicze do szybkiego użytku
def sha256_hash(data: str) -> str:
    """
    Szybka funkcja do obliczenia SHA-256 skrótu
    
    Parametry:
    - data: str - tekst do zhaszowania
    
    Zwraca: str - 64-znakowy heks skrótu
    
    Przykład:
        >>> sha256_hash("Cześć!")
        '3f7d8b9c...'  # 64 znakowy heks
    """
    hasher = SHA256Hash()
    return hasher.encrypt(data)


def sha256_bytes(data: bytes) -> bytes:
    """
    Oblicza SHA-256 skrót z danych binarnych
    
    Parametry:
    - data: bytes - dane do zhaszowania
    
    Zwraca: bytes - 32 bajty skrótu
    """
    return SHA256Hash.sha256(data)
