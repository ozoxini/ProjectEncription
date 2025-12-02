"""
Wymiana kluczy ECDH (Elliptic Curve Diffie-Hellman)
Prosty interfejs do:
1. Generacji par kluczy
2. Obliczania wspólnego sekretu
3. Szyfrowania/deszyfrowania wiadomości
"""

import base64
import hashlib
import os
import secrets
from typing import Any, Dict, Union

from .base_algorithm import BaseCryptoAlgorithm
from .elliptic_curve import Point, EllipticCurveP256
from .aes_core import AESCore


class ECDHKeyExchange(BaseCryptoAlgorithm):
    """
    ECDH - wymiana kluczy na bazie krzywej eliptycznej P-256
    
    Użycie:
    1. Każda osoba generuje parę: ecdh.generate_keypair()
    2. Wymieniają klucze publiczne (Base64)
    3. Każdy oblicza wspólny sekret: ecdh.compute_shared_secret(mój_prywatny, ich_publiczny_b64)
    4. Szyfrują wiadomości: ecdh.encrypt_message(tekst, wspólny_sekret)
    5. Deszyfrują: ecdh.decrypt_message(zaszyfrowana, wspólny_sekret)
    """
    
    def __init__(self):
        super().__init__(
            name="ECDH (P-256)",
            description="Wymiana kluczy na bazie krzywej eliptycznej P-256 (256 bitów)"
        )
        self.curve = EllipticCurveP256()
    
    # ========== GENERACJA PARY KLUCZY ==========
    
    def generate_keypair(self) -> Dict[str, Union[str, int]]:
        """
        Generuje nową parę kluczy ECDH.
        
        Zwraca słownik:
        {
            'private_key_int': int (256-bitowy klucz prywatny),
            'private_key_hex': str (heksadecymalny format),
            'public_key_b64': str (Base64 - do wysłania drugiej osobie),
        }
        
        Matematyka: publiczny = prywatny × G (punkt bazowy)
        """
        # 1. Wygeneruj losowy 256-bitowy klucz prywatny
        while True:
            private_key = secrets.randbits(256)
            # Sprawdź czy jest w prawidłowym zakresie [1, n-1]
            if 1 <= private_key < self.curve.n:
                break
        
        # 2. Oblicz klucz publiczny: public = private × G
        public_point = private_key * self.curve.G
        
        # 3. Konwertuj punkt na bajty: 0x04 || x(32B) || y(32B)
        public_bytes = public_point.to_bytes()
        
        # 4. Zakoduj do Base64 (łatwy do wysłania)
        public_b64 = base64.b64encode(public_bytes).decode('ascii')
        
        return {
            'private_key_int': private_key,
            'private_key_hex': hex(private_key)[2:].zfill(64),
            'public_key_b64': public_b64,
        }
    
    # ========== OBLICZANIE WSPÓLNEGO SEKRETU ==========
    
    def compute_shared_secret(self, my_private_key: int, 
                            their_public_key_b64: str) -> bytes:
        """
        Oblicza wspólny sekret.
        
        Parametry:
        - my_private_key: int (twój klucz prywatny)
        - their_public_key_b64: str (Base64 ich klucza publicznego)
        
        Zwraca: 32 bajty (256 bitów) - wspólny sekret
        
        Matematyka:
        1. Zdekoduj ich klucz publiczny: Point
        2. shared_point = mój_prywatny × ich_publiczny
        3. shared_secret = SHA-256(shared_point.x)
        """
        # 1. Zdekoduj ich klucz publiczny z Base64
        their_public_bytes = base64.b64decode(their_public_key_b64)
        their_public_point = Point.from_bytes(their_public_bytes)
        
        # 2. Oblicz wspólny punkt: my_private × their_public
        shared_point = my_private_key * their_public_point
        
        if shared_point.is_at_infinity():
            raise ValueError("Wspólny punkt jest w nieskończoności - coś poszło źle!")
        
        # 3. Haszuj x-współrzędną wspólnego punktu (to jest sekret)
        x_bytes = shared_point.x.to_bytes(32, 'big')
        shared_secret = hashlib.sha256(x_bytes).digest()
        
        return shared_secret  # 32 bajty
    
    # ========== SZYFROWANIE / DESZYFROWANIE ==========
    
    def encrypt_message(self, plaintext: str, shared_secret: bytes) -> str:
        """
        Szyfruje wiadomość wspólnym sekretem.
        
        Parametry:
        - plaintext: str (wiadomość do wysłania)
        - shared_secret: bytes (wspólny sekret z ECDH)
        
        Zwraca: str (Base64 - zaszyfrowana wiadomość do wysłania)
        
        Metoda: AES-256-CTR
        """
        # 1. Przygotuj AES-256
        core = AESCore(key_size=32)  # 256 bitów = 32 bajty
        expanded_key = core.expand_key(shared_secret)
        
        # 2. Wygeneruj losowy nonce (16 bajtów)
        nonce = os.urandom(16)
        
        # 3. Konwertuj tekst na bajty
        plaintext_bytes = plaintext.encode('utf-8')
        
        # 4. Szyfruj w trybie CTR
        ciphertext = self._ctr_encrypt(core, plaintext_bytes, expanded_key, nonce)
        
        # 5. Zwróć Base64(nonce + ciphertext)
        result = base64.b64encode(nonce + ciphertext).decode('ascii')
        return result
    
    def decrypt_message(self, encrypted_b64: str, shared_secret: bytes) -> str:
        """
        Deszyfruje wiadomość wspólnym sekretem.
        
        Parametry:
        - encrypted_b64: str (Base64 zaszyfrowanej wiadomości)
        - shared_secret: bytes (wspólny sekret z ECDH)
        
        Zwraca: str (odszyfrowana wiadomość)
        """
        # 1. Zdekoduj z Base64
        encrypted_bytes = base64.b64decode(encrypted_b64)
        
        # 2. Wyodrębnij nonce i ciphertext
        if len(encrypted_bytes) < 16:
            raise ValueError("Zaszyfrowana wiadomość za krótka!")
        
        nonce = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        # 3. Przygotuj AES-256
        core = AESCore(key_size=32)
        expanded_key = core.expand_key(shared_secret)
        
        # 4. Deszyfruj (CTR mode - operacja jest symetryczna)
        plaintext_bytes = self._ctr_encrypt(core, ciphertext, expanded_key, nonce)
        
        # 5. Konwertuj na tekst
        plaintext = plaintext_bytes.decode('utf-8')
        return plaintext
    
    # ========== TRYB CTR (AES) ==========
    
    def _ctr_encrypt(self, core: AESCore, data: bytes, 
                     expanded_key: list, nonce: bytes) -> bytes:
        """
        Szyfrowanie w trybie CTR (licznik).
        W CTR: szyfrowanie = deszyfrowanie (symetryczne)
        
        Blok licznika: nonce(16B) || counter(8B) = 24B total, ale AES bierze 16B
        Więc używamy: nonce(8B) || counter(8B) = 16B
        """
        output = b''
        counter = 0
        nonce_short = nonce[:8]  # Użyj pierwszych 8 bajtów nonce'a
        
        for i in range(0, len(data), 16):
            # Stwórz blok licznika: nonce || counter
            counter_block = nonce_short + counter.to_bytes(8, 'big')
            
            # Zaszyfruj blok licznika (to daje keystream)
            keystream = core.encrypt_block(counter_block, expanded_key)
            
            # XOR z danymi
            chunk = data[i:i+16]
            encrypted_chunk = bytes(a ^ b for a, b in zip(chunk, keystream[:len(chunk)]))
            output += encrypted_chunk
            
            counter += 1
        
        return output
    
    # ========== WYMAGANE METODY Z BaseCryptoAlgorithm ==========
    
    def validate_key(self, key: Any) -> bool:
        """ECDH nie używa tradycyjnego 'key' - zwróć True"""
        return True
    
    def encrypt(self, data: str, key: Any, **options) -> str:
        """Nie używany - użyj encrypt_message() zamiast"""
        raise NotImplementedError(
            "Użyj encrypt_message(text, shared_secret) zamiast encrypt()"
        )
    
    def decrypt(self, data: str, key: Any, **options) -> str:
        """Nie używany - użyj decrypt_message() zamiast"""
        raise NotImplementedError(
            "Użyj decrypt_message(encrypted_b64, shared_secret) zamiast decrypt()"
        )
