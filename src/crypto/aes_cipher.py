import base64
from typing import Any, Union
from .base_algorithm import BaseCryptoAlgorithm

# --- Stałe algorytmu AES ---

# To jest serce AES: S-Box (Substitution Box)
# Wykorzystywany w operacji SubBytes.
S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)

# Odwrotny S-Box (Inverse S-Box)
# Wykorzystywany w operacji InvSubBytes.
INV_S_BOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
)

# Stałe rundy (Round Constants) dla KeySchedule
RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
)


class AesCipher(BaseCryptoAlgorithm):


    def __init__(self):
        super().__init__(
            name="Szyfr AES 128-bit ECB",
            description="Implementacja AES-128 (ECB, PKCS#7)"
        )
        self.block_size = 16  # AES zawsze ma blok 16 bajtów
        self.key_size = 16    # AES-128 używa klucza 16 bajtów
        self.num_rounds = 10  # AES-128 ma 10 rund

    def validate_key(self, key: Any) -> bool:
        """Klucz musi być tekstem (str) i nie może być pusty."""
        return isinstance(key, str) and len(key) > 0

    # --- Funkcje pomocnicze do matematyki w ciele Galois (GF(2^8)) ---

    def _gmul(self, a: int, b: int) -> int:
        """
        Mnożenie dwóch bajtów w ciele Galois GF(2^8) 
        używane w MixColumns.
        """
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1B  # 0x1B to x^8 + x^4 + x^3 + x + 1 (wielomian AES)
            a &= 0xFF  # Upewnij się, że pozostaje w 8 bitach
            b >>= 1
        return p

    # --- Cztery główne operacje AES (i ich odwrotności) ---

    def _sub_bytes(self, state: list[int]) -> list[int]:
        """Operacja SubBytes: Zamienia każdy bajt stanu używając S-Box."""
        return [S_BOX[b] for b in state]

    def _inv_sub_bytes(self, state: list[int]) -> list[int]:
        """Operacja InvSubBytes: Zamienia każdy bajt stanu używając InvS-Box."""
        return [INV_S_BOX[b] for b in state]

    def _shift_rows(self, state: list[int]) -> list[int]:
        """
        Operacja ShiftRows: Przesuwa cyklicznie wiersze stanu.
        Stan jest 16-bajtową listą (traktowaną jako macierz 4x4 kolumnami).
        [ 0,  4,  8, 12 ]
        [ 1,  5,  9, 13 ]
        [ 2,  6, 10, 14 ]
        [ 3,  7, 11, 15 ]
        
        Wiersz 0: bez zmian
        Wiersz 1: przesunięcie o 1 w lewo [ 1,  5,  9, 13 ] -> [ 5,  9, 13,  1 ]
        Wiersz 2: przesunięcie o 2 w lewo [ 2,  6, 10, 14 ] -> [ 10, 14,  2,  6 ]
        Wiersz 3: przesunięcie o 3 w lewo [ 3,  7, 11, 15 ] -> [ 15,  3,  7, 11 ]
        """
        new_state = [0] * 16
        new_state[0] = state[0]
        new_state[4] = state[4]
        new_state[8] = state[8]
        new_state[12] = state[12]
        
        new_state[1] = state[5]
        new_state[5] = state[9]
        new_state[9] = state[13]
        new_state[13] = state[1]
        
        new_state[2] = state[10]
        new_state[6] = state[14]
        new_state[10] = state[2]
        new_state[14] = state[6]
        
        new_state[3] = state[15]
        new_state[7] = state[3]
        new_state[11] = state[7]
        new_state[15] = state[11]
        
        return new_state

    def _inv_shift_rows(self, state: list[int]) -> list[int]:
        """Operacja InvShiftRows: Odwrotne przesunięcie (w prawo)."""
        new_state = [0] * 16
        new_state[0] = state[0]
        new_state[4] = state[4]
        new_state[8] = state[8]
        new_state[12] = state[12]

        new_state[1] = state[13]
        new_state[5] = state[1]
        new_state[9] = state[5]
        new_state[13] = state[9]

        new_state[2] = state[10]
        new_state[6] = state[14]
        new_state[10] = state[2]
        new_state[14] = state[6]

        new_state[3] = state[7]
        new_state[7] = state[11]
        new_state[11] = state[15]
        new_state[15] = state[3]
        
        return new_state

    def _mix_columns(self, state: list[int]) -> list[int]:
        """
        Operacja MixColumns: Miesza każdą kolumnę stanu.
        Mnożenie przez stałą macierz w ciele Galois.
        """
        new_state = [0] * 16
        for c in range(4): # Dla każdej z 4 kolumn
            i = c * 4 # Indeks startowy kolumny
            s0 = state[i]
            s1 = state[i+1]
            s2 = state[i+2]
            s3 = state[i+3]
            
            new_state[i]   = self._gmul(s0, 2) ^ self._gmul(s1, 3) ^ self._gmul(s2, 1) ^ self._gmul(s3, 1)
            new_state[i+1] = self._gmul(s0, 1) ^ self._gmul(s1, 2) ^ self._gmul(s2, 3) ^ self._gmul(s3, 1)
            new_state[i+2] = self._gmul(s0, 1) ^ self._gmul(s1, 1) ^ self._gmul(s2, 2) ^ self._gmul(s3, 3)
            new_state[i+3] = self._gmul(s0, 3) ^ self._gmul(s1, 1) ^ self._gmul(s2, 1) ^ self._gmul(s3, 2)
        return new_state

    def _inv_mix_columns(self, state: list[int]) -> list[int]:
        """
        Operacja InvMixColumns: Odwrotne mieszanie kolumn.
        Mnożenie przez inną stałą macierz.
        """
        new_state = [0] * 16
        for c in range(4): # Dla każdej z 4 kolumn
            i = c * 4 # Indeks startowy kolumny
            s0 = state[i]
            s1 = state[i+1]
            s2 = state[i+2]
            s3 = state[i+3]

            new_state[i]   = self._gmul(s0, 0x0E) ^ self._gmul(s1, 0x0B) ^ self._gmul(s2, 0x0D) ^ self._gmul(s3, 0x09)
            new_state[i+1] = self._gmul(s0, 0x09) ^ self._gmul(s1, 0x0E) ^ self._gmul(s2, 0x0B) ^ self._gmul(s3, 0x0D)
            new_state[i+2] = self._gmul(s0, 0x0D) ^ self._gmul(s1, 0x09) ^ self._gmul(s2, 0x0E) ^ self._gmul(s3, 0x0B)
            new_state[i+3] = self._gmul(s0, 0x0B) ^ self._gmul(s1, 0x0D) ^ self._gmul(s2, 0x09) ^ self._gmul(s3, 0x0E)
        return new_state

    def _add_round_key(self, state: list[int], round_key: list[int]) -> list[int]:
        """Operacja AddRoundKey: XOR stanu z kluczem rundy."""
        return [state[i] ^ round_key[i] for i in range(16)]

    # --- Algorytm Rozszerzania Klucza (Key Expansion / Key Schedule) ---
    
    def _expand_key(self, key_bytes: bytes) -> list[list[int]]:
        """
        Rozszerza 16-bajtowy klucz główny na 11 kluczy rund
        (1 klucz główny + 10 kluczy rund).
        Zwraca listę 11 list, każda po 16 bajtów.
        """
        # Upewnij się, że klucz ma 16 bajtów
        if len(key_bytes) != self.key_size:
            raise ValueError(f"Klucz musi mieć {self.key_size} bajtów.")

        key = list(key_bytes)
        
        # Liczba słów klucza (Nk = 4 dla AES-128)
        # Liczba rund (Nr = 10 dla AES-128)
        # Liczba bajtów w rozszerzonym kluczu: 16 * (10 + 1) = 176
        expanded_key = [0] * (self.block_size * (self.num_rounds + 1))
        
        # Pierwsze 16 bajtów to klucz główny
        expanded_key[:self.key_size] = key
        
        # Pętla generująca pozostałe klucze
        for i in range(self.key_size, len(expanded_key), 4):
            # 'temp' to poprzednie 4-bajtowe słowo (w[i-1])
            temp = expanded_key[i-4 : i]
            
            # Co 16 bajtów (co 4 słowa) wykonujemy specjalne operacje
            if i % self.key_size == 0:
                # 1. RotWord (rotacja w lewo)
                temp = [temp[1], temp[2], temp[3], temp[0]]
                # 2. SubWord (przez S-Box)
                temp = [S_BOX[b] for b in temp]
                # 3. Rcon (XOR ze stałą rundy)
                rcon_index = i // self.key_size
                temp[0] ^= RCON[rcon_index]

            # w[i] = w[i-Nk] ^ temp (dla AES-128, Nk=4, więc w[i-Nk] = w[i-16])
            for j in range(4):
                expanded_key[i + j] = expanded_key[i - self.key_size + j] ^ temp[j]
        
        # Zwróć jako listę kluczy rund (każdy 16 bajtów)
        return [expanded_key[i : i+16] for i in range(0, len(expanded_key), 16)]


    # --- Główne funkcje szyfrowania i deszyfrowania bloku ---

    def _szyfruj_blok(self, blok_jawny: bytes, expanded_key: list[list[int]]) -> bytes:
        """Szyruje pojedynczy 16-bajtowy blok tekstu jawnego."""
        
        state = list(blok_jawny)
        
        # Runda 0: Tylko AddRoundKey
        state = self._add_round_key(state, expanded_key[0])
        
        # Rundy 1 do 9: Pełne rundy
        for i in range(1, self.num_rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, expanded_key[i])
            
        # Runda 10 (ostatnia): Bez MixColumns
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, expanded_key[self.num_rounds])
        
        return bytes(state)

    def _deszyfruj_blok(self, blok_szyfrogramu: bytes, expanded_key: list[list[int]]) -> bytes:
        """Deszyfruje pojedynczy 16-bajtowy blok szyfrogramu."""
        
        state = list(blok_szyfrogramu)

        # Runda 0 (odwrotność rundy 10):
        state = self._add_round_key(state, expanded_key[self.num_rounds])
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)

        # Rundy 1 do 9 (odwrotność rund 9 do 1):
        for i in range(self.num_rounds - 1, 0, -1):
            state = self._add_round_key(state, expanded_key[i])
            state = self._inv_mix_columns(state)
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            
        # Runda 10 (odwrotność rundy 0):
        state = self._add_round_key(state, expanded_key[0])
        
        return bytes(state)

    # --- Metody z interfejsu BaseCryptoAlgorithm ---

    def _prepare_key(self, key_str: str) -> bytes:
        """
        Konwertuje klucz (str) na bajty (utf-8) i przycina/dopełnia 
        do wymaganego rozmiaru (16 bajtów dla AES-128).
        """
        key_bytes = key_str.encode('utf-8')
        # ljust dopełnia bajtami \x00, [:self.key_size] ucina
        return key_bytes.ljust(self.key_size, b'\x00')[:self.key_size]

    def _pad(self, dane: bytes) -> bytes:
        """Dopełnia dane do wielokrotności rozmiaru bloku (PKCS#7)."""
        ilosc_brakujaca = self.block_size - (len(dane) % self.block_size)
        bajt_dopelnienia = bytes([ilosc_brakujaca])
        return dane + bajt_dopelnienia * ilosc_brakujaca

    def _unpad(self, dane: bytes) -> bytes:
        """Usuwa dopełnienie PKCS#7 z danych."""
        if not dane:
            raise ValueError("Puste dane do od-dopełnienia")
        
        ilosc_dopelnienia = dane[-1]

        if ilosc_dopelnienia == 0 or ilosc_dopelnienia > self.block_size:
            raise ValueError("Błędna wartość dopełnienia")
        
        if dane[-ilosc_dopelnienia:] != bytes([ilosc_dopelnienia]) * ilosc_dopelnienia:
            raise ValueError("Błędne bajty dopełnienia")

        return dane[:-ilosc_dopelnienia]

    def encrypt(self, data: Union[str, bytes], key: Any) -> Union[str, bytes]:
        """Szyfruje dane w trybie AES-128-ECB."""
        
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

        # --- Główne zmiany ---
        # 1. Przygotuj 16-bajtowy klucz główny
        key_bytes = self._prepare_key(key)
        # 2. Rozszerz klucz na wszystkie klucze rund
        try:
            expanded_key = self._expand_key(key_bytes)
        except ValueError as e:
            raise ValueError(f"Błąd klucza: {e}")
        # --------------------

        padded_data = self._pad(data_bytes)
        encrypted_bytes = b''

        for i in range(0, len(padded_data), self.block_size):
            blok = padded_data[i : i + self.block_size]
            # Przekaż rozszerzony klucz do funkcji szyfrującej blok
            encrypted_bytes += self._szyfruj_blok(blok, expanded_key) 

        if return_text:
            return base64.b64encode(encrypted_bytes).decode('utf-8')
        return encrypted_bytes

    def decrypt(self, data: Union[str, bytes], key: Any) -> Union[str, bytes]:
        """Deszyfruje dane w trybie AES-128-ECB."""
        
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
        
        if len(enc_bytes) % self.block_size != 0:
            raise ValueError("Dane szyfrogramu mają nieprawidłową długość.")

        # --- Główne zmiany ---
        # 1. Przygotuj 16-bajtowy klucz główny
        key_bytes = self._prepare_key(key)
        # 2. Rozszerz klucz na wszystkie klucze rund
        try:
            expanded_key = self._expand_key(key_bytes)
        except ValueError as e:
            raise ValueError(f"Błąd klucza: {e}")
        # --------------------

        decrypted_padded_bytes = b''

        for i in range(0, len(enc_bytes), self.block_size):
            blok = enc_bytes[i : i + self.block_size]
            # Przekaż rozszerzony klucz do funkcji deszyfrującej blok
            decrypted_padded_bytes += self._deszyfruj_blok(blok, expanded_key)

        try:
            decrypted_bytes = self._unpad(decrypted_padded_bytes)
        except ValueError as e:
            raise ValueError(f"Błąd deszyfrowania: {e}. Prawdopodobnie zły klucz.")

        if return_text:
            try:
                return decrypted_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # To się może zdarzyć, jeśli odszyfrowane dane nie są poprawnym UTF-8
                raise ValueError("Błąd deszyfrowania: Zły klucz lub dane nie są tekstem UTF-8.")
        return decrypted_bytes