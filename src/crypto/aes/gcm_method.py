import base64
import os
from typing import Any, Union
from ..base_algorithm import BaseCryptoAlgorithm
from ..aes_core import AESCore  # <-- Import silnika

# --- Funkcje pomocnicze ---

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Wykonuje operację XOR bajt po bajcie."""
    length = min(len(a), len(b))
    return bytes(a[i] ^ b[i] for i in range(length))

def _bytes_to_int(b: bytes) -> int:
    """Konwertuje bajty (big-endian) na liczbę całkowitą."""
    return int.from_bytes(b, 'big')

def _int_to_bytes(i: int, length: int = 16) -> bytes:
    """Konwertuje liczbę całkowitą na bajty (big-endian)."""
    return i.to_bytes(length, 'big')

def _timing_safe_compare(a: bytes, b: bytes) -> bool:
    """
    Porównanie odporne na ataki czasowe.
    Kluczowe dla weryfikacji tagu MAC.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

class GcmMethod(BaseCryptoAlgorithm):
    """
    Implementacja AES w trybie GCM (Galois/Counter Mode).
    Jest to tryb AEAD (szyfrowanie z uwierzytelnianiem).
    
    OSTRZEŻENIE: Implementacja "od zera" jest bardzo złożona.
    Ta wersja zakłada brak dodatkowych danych uwierzytelniających (AAD).
    """
    def __init__(self):
        super().__init__(
            name="AES (GCM)",
            description="AES w trybie AEAD (uwierzytelnianie + szyfrowanie)."
        )
        self.block_size = 16 # 16 bajtów
        self.tag_size = 16 # Standardowy tag GCM ma 16 bajtów
        self.nonce_size = 12 # Standardowy nonce GCM ma 12 bajtów

    # --- Identyczne funkcje validate/prepare ---
    def validate_key(self, key: Any) -> bool:
        return isinstance(key, str) and len(key) > 0

    def _prepare_key(self, key_str: str, key_size: int) -> bytes:
        key_bytes = key_str.encode('utf-8')
        return key_bytes.ljust(key_size, b'\x00')[:key_size]

    # --- Tryb GCM (oparty na CTR) nie używa Paddingu! ---

    # --- Logika GHASH (serce GCM) ---
    
    def _ghash_multiply(self, x: int, y: int) -> int:
        """
        Mnożenie w ciele Galois GF(2^128).
        To jest serce funkcji GHASH.
        """
        # R to wielomian redukcyjny: x^128 + x^7 + x^2 + x + 1
        R = 0xE1000000000000000000000000000000
        z = 0
        v = y
        
        for i in range(127, -1, -1):
            if (x >> i) & 1:
                z ^= v  # z = z + v (w GF(2^n) dodawanie to XOR)
            
            if v & 1:
                v = (v >> 1) ^ R
            else:
                v = v >> 1
        return z

    def _ghash_calculate(self, H_int: int, aad: bytes, ciphertext: bytes) -> bytes:
        """
        Oblicza pełny GHASH na podstawie AAD i szyfrogramu.
        """
        # 1. Dopełnij AAD do wielokrotności 16 bajtów
        aad_padded = aad + (b'\x00' * ((16 - len(aad) % 16) % 16))
        
        # 2. Dopełnij szyfrogram do wielokrotności 16 bajtów
        ct_padded = ciphertext + (b'\x00' * ((16 - len(ciphertext) % 16) % 16))
        
        # 3. Połącz dane
        data_to_hash = aad_padded + ct_padded
        
        # 4. Dołącz bloki długości (w bitach)
        len_aad_bits = len(aad) * 8
        len_ct_bits = len(ciphertext) * 8
        len_block = _int_to_bytes(len_aad_bits, 8) + _int_to_bytes(len_ct_bits, 8)
        
        data_to_hash += len_block
        
        # 5. Wykonaj haszowanie (mnożenie blok po bloku)
        current_hash_int = 0
        for i in range(0, len(data_to_hash), 16):
            block = data_to_hash[i:i+16]
            block_int = _bytes_to_int(block)
            
            # Y_i = (Y_{i-1} ⊕ P_i) * H
            current_hash_int = self._ghash_multiply(current_hash_int ^ block_int, H_int)
            
        return _int_to_bytes(current_hash_int)

    def _ctr_xor_operation(self, core: AESCore, data: bytes, expanded_key: list[list[int]], J0: bytes) -> bytes:
        """
        Logika szyfrowania trybu CTR, ale startująca od licznika J0.
        """
        output = b''
        
        # Licznik (CTR) w GCM zaczyna się od J0 + 1
        counter_int = _bytes_to_int(J0)
        
        # Pętla po blokach danych
        for i in range(0, len(data), self.block_size):
            # Inkrementuj licznik PRZED szyfrowaniem
            counter_int = (counter_int + 1) % (2**128)
            counter_block = _int_to_bytes(counter_int)
            
            # Zaszyfruj blok licznika, aby otrzymać "bełkot"
            keystream = core.encrypt_block(counter_block, expanded_key)
            
            chunk = data[i : i + self.block_size]
            output += xor_bytes(chunk, keystream)
            
        return output

    def encrypt(self, data: Union[str, bytes], key: Any, **options) -> Union[str, bytes]:
        if not self.validate_key(key):
            raise ValueError("Nieprawidłowy klucz.")

        key_size = options.get('key_size', 16)
        core = AESCore(key_size)

        return_text = False
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
            return_text = True
        elif isinstance(data, (bytes, bytearray)):
            data_bytes = bytes(data)
        else:
            raise TypeError("Dane muszą być typu str lub bytes")

        try:
            # --- Przygotowanie ---
            key_bytes = self._prepare_key(key, core.key_size)
            expanded_key = core.expand_key(key_bytes)
            
            # 1. Wygeneruj klucz H dla GHASH
            # H = E_k(0^128)
            H_bytes = core.encrypt_block(b'\x00' * 16, expanded_key)
            H_int = _bytes_to_int(H_bytes)
            
            # 2. Wygeneruj losowy 12-bajtowy Nonce
            nonce = os.urandom(self.nonce_size)
            
            # 3. Przygotuj pierwszy blok licznika J0
            # J0 = Nonce || 0x00000001
            J0 = nonce + b'\x00\x00\x00\x01'
            
            # 4. Szyfrowanie (Tryb CTR)
            ciphertext = self._ctr_xor_operation(core, data_bytes, expanded_key, J0)
            
            # 5. Obliczanie Tagu (GHASH)
            # AAD (Associated Data) jest puste w naszej implementacji
            aad = b''
            ghash = self._ghash_calculate(H_int, aad, ciphertext)
            
            # 6. Zaszyfruj J0
            S0 = core.encrypt_block(J0, expanded_key)
            
            # 7. Tag T = GHASH ⊕ S0
            tag = xor_bytes(ghash, S0)[:self.tag_size]
            
            # 8. Połącz: Nonce + Szyfrogram + Tag
            final_output_bytes = nonce + ciphertext + tag
            
        except Exception as e:
            raise RuntimeError(f"Błąd podczas szyfrowania GCM: {e}")

        if return_text:
            return base64.b64encode(final_output_bytes).decode('utf-8')
        return final_output_bytes

    def decrypt(self, data: Union[str, bytes], key: Any, **options) -> Union[str, bytes]:
        if not self.validate_key(key):
            raise ValueError("Nieprawidłowy klucz.")

        key_size = options.get('key_size', 16)
        core = AESCore(key_size)

        return_text = False
        if isinstance(data, str):
            try:
                enc_bytes = base64.b64decode(data)
                return_text = True
            except Exception:
                raise ValueError("Nieprawidłowy format base64")
        elif isinstance(data, (bytes, bytearray)):
            enc_bytes = bytes(data)
        else:
            raise TypeError("Dane muszą być typu str lub bytes")

        # Sprawdź, czy dane mają minimalną długość (Nonce + Tag)
        if len(enc_bytes) < self.nonce_size + self.tag_size:
            raise ValueError("Uszkodzone dane. Za krótkie.")

        try:
            # --- Przygotowanie ---
            key_bytes = self._prepare_key(key, core.key_size)
            expanded_key = core.expand_key(key_bytes)
            
            # 1. Wygeneruj klucz H dla GHASH
            H_bytes = core.encrypt_block(b'\x00' * 16, expanded_key)
            H_int = _bytes_to_int(H_bytes)
            
            # 2. Wyodrębnij komponenty
            nonce = enc_bytes[:self.nonce_size]
            ciphertext = enc_bytes[self.nonce_size:-self.tag_size]
            received_tag = enc_bytes[-self.tag_size:]
            
            # 3. Przygotuj J0
            J0 = nonce + b'\x00\x00\x00\x01'
            
            # 4. Oblicz oczekiwany Tag (GHASH)
            aad = b''
            ghash = self._ghash_calculate(H_int, aad, ciphertext)
            S0 = core.encrypt_block(J0, expanded_key)
            expected_tag = xor_bytes(ghash, S0)[:self.tag_size]
            
            # 5. Weryfikacja Tagu (Kluczowy krok!)
            if not _timing_safe_compare(received_tag, expected_tag):
                raise ValueError("Błąd uwierzytelniania! Dane są uszkodzone lub klucz jest zły.")
                
            # 6. Deszyfrowanie (Tryb CTR) - tylko jeśli tag jest poprawny
            decrypted_bytes = self._ctr_xor_operation(core, ciphertext, expanded_key, J0)

        except ValueError as e:
            # Przekaż błąd (np. "Błąd uwierzytelniania!")
            raise e
        except Exception as e:
            raise RuntimeError(f"Błąd deszyfrowania GCM: {e}")

        if return_text:
            try:
                return decrypted_bytes.decode('utf-8')
            except UnicodeDecodeError:
                raise ValueError("Błąd deszyfrowania: Zły klucz lub dane nie są tekstem UTF-8.")
        return decrypted_bytes
