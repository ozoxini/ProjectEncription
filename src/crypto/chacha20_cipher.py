import base64
import hashlib
import os
import struct
from typing import Any, Union, List


from .base_algorithm import BaseCryptoAlgorithm



def _rotl(val: int, bits: int) -> int:
    """Rotacja bitowa w lewo (32-bit)"""
    val &= 0xFFFFFFFF
    return ((val << bits) & 0xFFFFFFFF) | (val >> (32 - bits))

def _add_32(a: int, b: int) -> int:
    """Dodawanie modulo 2^32"""
    return (a + b) & 0xFFFFFFFF

def _chacha20_quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    """Operacja Quarter Round (ARX) w miejscu na stanie"""
    state[a] = _add_32(state[a], state[b])
    state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = _add_32(state[c], state[d])
    state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = _add_32(state[a], state[b])
    state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = _add_32(state[c], state[d])
    state[b] = _rotl(state[b] ^ state[c], 7)

def _chacha20_core(key: bytes, nonce: bytes, counter: int) -> bytes:
    """Generuje jeden 64-bajtowy blok strumienia klucza ChaCha20"""
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = list(struct.unpack('<8I', key))
    nonce_words = list(struct.unpack('<3I', nonce))
    
    initial_state = constants + key_words + [counter] + nonce_words
    state = list(initial_state)

    for _ in range(10): # 10 rund podwójnych = 20 rund
        _chacha20_quarter_round(state, 0, 4, 8, 12) # Kolumny
        _chacha20_quarter_round(state, 1, 5, 9, 13)
        _chacha20_quarter_round(state, 2, 6, 10, 14)
        _chacha20_quarter_round(state, 3, 7, 11, 15)
        _chacha20_quarter_round(state, 0, 5, 10, 15) # Przekątne
        _chacha20_quarter_round(state, 1, 6, 11, 12)
        _chacha20_quarter_round(state, 2, 7, 8, 13)
        _chacha20_quarter_round(state, 3, 4, 9, 14)

    final_state = [_add_32(initial_state[i], state[i]) for i in range(16)]
    return struct.pack('<16I', *final_state)

def _chacha20_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Szyfruje/deszyfruje dane przy użyciu ChaCha20"""
    output = bytearray()
    counter = 1 # Zaczynamy licznik od 1 (standard)
    
    for i in range(0, len(data), 64):
        keystream_block = _chacha20_core(key, nonce, counter)
        chunk = data[i : i + 64]
        
        for j in range(len(chunk)):
            output.append(chunk[j] ^ keystream_block[j])
        
        counter = _add_32(counter, 1)
        
    return bytes(output)

# --- Klasa zgodna z Twoim BaseCryptoAlgorithm ---

class ChaCha20Cipher(BaseCryptoAlgorithm):

    def __init__(self):
        super().__init__(
            name="Szyfr ChaCha20",
            description="Szybki szyfr strumieniowy"
        )
        self.key_size = 32 # 256 bitów
        self.nonce_size = 12 # 96 bitów

    def validate_key(self, key: Any) -> bool:
        """Klucz musi być tekstem (str) i nie może być pusty."""
        return isinstance(key, str) and len(key) > 0

    def _prepare_key(self, key_str: str) -> bytes:

        return hashlib.sha256(key_str.encode('utf-8')).digest()

    def encrypt(self, data: Union[str, bytes], key: Any) -> Union[str, bytes]:
        """Szyfruje dane (str lub bytes)"""
        
        if not self.validate_key(key):
            raise ValueError("Nieprawidłowy klucz.")

  
        return_text = False
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
            return_text = True
        elif isinstance(data, (bytes, bytearray)):
            data_bytes = bytes(data)
        else:
            raise TypeError("Dane do zaszyfrowania muszą być typu str lub bytes")

        # --- Logika ChaCha20 ---
        try:
            # 1. Przygotuj klucz
            key_bytes = self._prepare_key(key)
            
            # 2. Wygeneruj bezpieczny, losowy nonce
            nonce = os.urandom(self.nonce_size)
            
            # 3. Zaszyfruj dane (używając wewnętrznej logiki)
            encrypted_data = _chacha20_xor(key_bytes, nonce, data_bytes)
            
            # 4. Dołącz nonce DO POCZĄTKU szyfrogramu
            final_output_bytes = nonce + encrypted_data

        except Exception as e:
            raise RuntimeError(f"Błąd podczas szyfrowania ChaCha20: {e}")

        # --- Zwracanie wyniku (tak jak w AesCipher) ---
        if return_text:
            return base64.b64encode(final_output_bytes).decode('utf-8')
        return final_output_bytes

    def decrypt(self, data: Union[str, bytes], key: Any) -> Union[str, bytes]:
        """Deszyfruje dane (str lub bytes)"""
        
        if not self.validate_key(key):
            raise ValueError("Nieprawidłowy klucz.")

        # --- Przygotowanie danych (tak jak w AesCipher) ---
        return_text = False
        if isinstance(data, str):
            try:
                data_bytes = base64.b64decode(data)
                return_text = True
            except Exception:
                raise ValueError("Nieprawidłowy format danych (oczekiwany base64)")
        elif isinstance(data, (bytes, bytearray)):
            data_bytes = bytes(data)
        else:
            raise TypeError("Dane do odszyfrowania muszą być typu str lub bytes")

        # --- Logika ChaCha20 ---
        
        # Sprawdź, czy dane nie są za krótkie (muszą zawierać przynajmniej nonce)
        if len(data_bytes) < self.nonce_size:
            raise ValueError("Uszkodzone dane. Za krótkie, by zawierać nonce.")

        try:
            # 1. Przygotuj klucz
            key_bytes = self._prepare_key(key)
            
            # 2. Wyodrębnij nonce (pierwsze 12 bajtów)
            nonce = data_bytes[:self.nonce_size]
            
            # 3. Wyodrębnij właściwy szyfrogram (reszta)
            ciphertext = data_bytes[self.nonce_size:]
            
            # 4. Odszyfruj dane
            decrypted_bytes = _chacha20_xor(key_bytes, nonce, ciphertext)

        except Exception as e:
            raise RuntimeError(f"Błąd deszyfrowania ChaCha20: {e}. Prawdopodobnie zły klucz.")

        if return_text:
            try:
                return decrypted_bytes.decode('utf-8')
            except UnicodeDecodeError:
                raise ValueError("Błąd deszyfrowania: Zły klucz lub dane nie są tekstem UTF-8.")
        return decrypted_bytes