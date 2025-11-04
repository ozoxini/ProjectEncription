import base64
import os  # Do generowania losowego IV (Nonce)
from typing import Any, Union
from ..base_algorithm import BaseCryptoAlgorithm
from ..aes_core import AESCore  # <-- Import silnika


def xor_bytes(a: bytes, b: bytes) -> bytes:

    length = min(len(a), len(b))
    return bytes(a[i] ^ b[i] for i in range(length))

class CtrMethod(BaseCryptoAlgorithm):

    def __init__(self):
        super().__init__(
            name="AES-128 (CTR)",
            description="Standardowy AES w trybie licznika (szyfr strumieniowy)."
        )
        self.core = AESCore()
        self.block_size = self.core.block_size

    # --- Identyczne funkcje validate/prepare ---
    def validate_key(self, key: Any) -> bool:
        return isinstance(key, str) and len(key) > 0

    def _prepare_key(self, key_str: str) -> bytes:
        key_bytes = key_str.encode('utf-8')
        return key_bytes.ljust(self.core.key_size, b'\x00')[:self.core.key_size]
    
    # --- Tryb CTR nie używa Paddingu! ---

    def _ctr_xor_operation(self, data: bytes, expanded_key: list[list[int]], iv: bytes) -> bytes:
        """
        Główna pętla operacji CTR (identyczna dla szyfrowania i deszyfrowania).
        """
        output = b''
        
        # Traktujemy IV (Nonce) jako 128-bitową (16-bajtową) liczbę całkowitą
        # Będziemy ją inkrementować (zwiększać o 1) dla każdego bloku
        counter_int = int.from_bytes(iv, 'big')

        for i in range(0, len(data), self.block_size):
            # 1. Zamień obecną wartość licznika na 16-bajtowy blok
            counter_block = counter_int.to_bytes(self.block_size, 'big')
            
            # 2. Zaszyfruj blok licznika, aby otrzymać "bełkot" (strumień klucza)
            keystream = self.core.encrypt_block(counter_block, expanded_key)
            
            # 3. Weź kawałek danych (w ostatniej pętli może być krótszy)
            chunk = data[i : i + self.block_size]
            
            # 4. Wykonaj XOR
            output += xor_bytes(chunk, keystream)
            
            # 5. Zwiększ licznik o 1 na potrzeby następnej pętli
            counter_int += 1
            
        return output

    def encrypt(self, data: Union[str, bytes], key: Any) -> Union[str, bytes]:
        """Szyfruje dane w trybie AES-CTR."""
        
        if not self.validate_key(key):
            raise ValueError("Nieprawidłowy klucz.")

        return_text = False
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
            return_text = True
        elif isinstance(data, (bytes, bytearray)):
            data_bytes = bytes(data)
        else:
            raise TypeError("Dane muszą być typu str lub bytes")

        try:
            key_bytes = self._prepare_key(key)
            expanded_key = self.core.expand_key(key_bytes)
            
            # 1. Wygeneruj losowy 16-bajtowy IV (Nonce)
            iv = os.urandom(self.block_size)
            
            # 2. Wykonaj operację CTR (XOR)
            encrypted_data = self._ctr_xor_operation(data_bytes, expanded_key, iv)
            
            # 3. Dołącz IV na początku szyfrogramu
            final_output_bytes = iv + encrypted_data
            
        except Exception as e:
            raise RuntimeError(f"Błąd podczas szyfrowania CTR: {e}")

        if return_text:
            return base64.b64encode(final_output_bytes).decode('utf-8')
        return final_output_bytes

    def decrypt(self, data: Union[str, bytes], key: Any) -> Union[str, bytes]:
        """Deszyfruje dane w trybie AES-CTR."""
        
        if not self.validate_key(key):
            raise ValueError("Nieprawidłowy klucz.")

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

        if len(enc_bytes) < self.block_size:
            raise ValueError("Uszkodzone dane. Za krótkie, by zawierać IV.")

        try:
            key_bytes = self._prepare_key(key)
            expanded_key = self.core.expand_key(key_bytes)
            
            # 1. Wyodrębnij IV (pierwsze 16 bajtów)
            iv = enc_bytes[:self.block_size]
            
            # 2. Wyodrębnij właściwy szyfrogram (reszta)
            ciphertext = enc_bytes[self.block_size:]
            
            # 3. Wykonaj operację CTR (XOR) - jest identyczna jak szyfrowanie!
            decrypted_bytes = self._ctr_xor_operation(ciphertext, expanded_key, iv)

        except Exception as e:
            raise RuntimeError(f"Błąd deszyfrowania CTR: {e}. Prawdopodobnie zły klucz.")

        if return_text:
            try:
                return decrypted_bytes.decode('utf-8')
            except UnicodeDecodeError:
                raise ValueError("Błąd deszyfrowania: Zły klucz lub dane nie są tekstem UTF-8.")
        return decrypted_bytes