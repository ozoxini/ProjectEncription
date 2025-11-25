"""
System logowania dla operacji kryptograficznych
"""

from typing import List, Optional, Any
from enum import Enum
from datetime import datetime


class LogLevel(Enum):
    """Poziomy logowania"""
    INFO = "INFO"
    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    ERROR = "ERROR"
    DEBUG = "DEBUG"


class LogEntry:
    """Pojedynczy wpis logu"""
    
    def __init__(self, level: LogLevel, message: str, details: Optional[str] = None, step: Optional[int] = None):
        self.level = level
        self.message = message
        self.details = details
        self.step = step  # Numer kroku w procesie
        
    def format_for_display(self) -> str:
        """Formatuje wpis do wyświetlenia"""
        # Symbole na podstawie poziomu (bez emoji)
        symbols = {
            LogLevel.INFO: "->",
            LogLevel.SUCCESS: "✓",
            LogLevel.WARNING: "!",
            LogLevel.ERROR: "X",
            LogLevel.DEBUG: "::"
        }
        
        symbol = symbols.get(self.level, "•")
        
        # Buduj wyświetlanie
        if self.step is not None:
            # Jeśli jest krok - pokaż wizualizację
            indent = "  " * (self.step - 1)
            formatted = f"{indent}[{self.step}] {symbol} {self.message}"
        else:
            formatted = f"{symbol} {self.message}"
        
        if self.details:
            detail_indent = "  " * (self.step if self.step else 0)
            formatted += f"\n{detail_indent}    └─ {self.details}"
        
        return formatted


class OperationLogger:
    """Logger dla operacji kryptograficznych"""
    
    def __init__(self):
        self.all_operations: List[dict] = []  # Historia wszystkich operacji
        self.current_operation: dict = None  # Aktualna operacja
        self.logs: List[LogEntry] = []
        self.current_algorithm: Optional[str] = None
        self.current_mode: Optional[str] = None
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.result: Optional[str] = None
        self.has_error: bool = False
        self.current_step: int = 0  # Śledzenie kroku procesu
    
    def add_log(self, level: LogLevel, message: str, details: Optional[str] = None, is_step: bool = False):
        """Dodaje wpis do logu"""
        # Jeśli to główny krok - inkrementuj licznik
        if is_step:
            self.current_step += 1
            entry = LogEntry(level, message, details, step=self.current_step)
        else:
            entry = LogEntry(level, message, details, step=self.current_step if self.current_step > 0 else None)
        
        self.logs.append(entry)
        return entry
    
    def info(self, message: str, details: Optional[str] = None, is_step: bool = False):
        """Dodaje log INFO"""
        return self.add_log(LogLevel.INFO, message, details, is_step=is_step)
    
    def success(self, message: str, details: Optional[str] = None, is_step: bool = False):
        """Dodaje log SUCCESS"""
        return self.add_log(LogLevel.SUCCESS, message, details, is_step=is_step)
    
    def warning(self, message: str, details: Optional[str] = None, is_step: bool = False):
        """Dodaje log WARNING"""
        return self.add_log(LogLevel.WARNING, message, details, is_step=is_step)
    
    def error(self, message: str, details: Optional[str] = None, is_step: bool = False):
        """Dodaje log ERROR"""
        return self.add_log(LogLevel.ERROR, message, details, is_step=is_step)
    
    def debug(self, message: str, details: Optional[str] = None, is_step: bool = False):
        """Dodaje log DEBUG"""
        return self.add_log(LogLevel.DEBUG, message, details, is_step=is_step)
    
    def log_input_preview(self, data: Any, label: str = "Dane wejściowe", is_step: bool = True):
        """Loguje podgląd danych wejściowych (rozmiar i fragment)"""
        if isinstance(data, bytes):
            size_str = f"{len(data)} bajtów"
            # Podgląd hex dla bajtów
            preview = data[:32].hex(' ')
            if len(data) > 32:
                preview += "..."
        else:
            text = str(data)
            size_str = f"{len(text)} znaków"
            # Podgląd tekstu (zamiana nowych linii na spacje)
            preview = text[:50].replace('\n', ' ')
            if len(text) > 50:
                preview += "..."
        
        self.info(label, f"Rozmiar: {size_str}", is_step=is_step)
        self.debug("Podgląd", preview)
    
    def set_algorithm(self, algorithm: str, mode: Optional[str] = None):
        """Ustawia aktualny algorytm i tryb - ROZPOCZYNA nową operację"""
        # Zapisz poprzednią operację do historii
        if self.current_operation:
            self.all_operations.append(self.current_operation)
        
        # Resetuj licznik kroków dla nowej operacji
        self.current_step = 0
        
        # Stwórz nową operację
        self.current_operation = {
            'algorithm': algorithm,
            'mode': mode,
            'start_time': datetime.now(),
            'end_time': None,
            'logs': [],
            'result': None,
            'has_error': False
        }
        
        # Ustaw dla kompatybilności z logami
        self.current_algorithm = algorithm
        self.current_mode = mode
        self.start_time = self.current_operation['start_time']
        self.logs = self.current_operation['logs']
    
    def set_result(self, result: str):
        """Ustawia rezultat operacji (ukryty)"""
        self.result = result
        self.end_time = datetime.now()
        if self.current_operation:
            self.current_operation['result'] = result
            self.current_operation['end_time'] = self.end_time
    
    def set_error(self):
        """Oznacza że operacja miała błąd"""
        self.has_error = True
        self.end_time = datetime.now()
        if self.current_operation:
            self.current_operation['has_error'] = True
            self.current_operation['end_time'] = self.end_time
    
    def explain_algorithm(self, algo_name: str, key: Any = None):
        """Dodaje wyjaśnienie działania algorytmu"""
        explanations = {
            "Szyfr Cezara": self._explain_caesar,
            "Szyfr Vigenere'a": self._explain_vigenere,
            "Szyfr Beauforta": self._explain_beaufort,
            "AES": self._explain_aes,
            "RSA": self._explain_rsa,
        }
        
        if algo_name in explanations:
            explanation = explanations[algo_name](key)
            self.info("Zasada działania", explanation)
    
    def _explain_caesar(self, key: int) -> str:
        """Wyjaśnienie Szyfru Cezara"""
        return f"Każda litera przesunięta o {key} pozycji w alfabecie (A->D gdy shift=3)"
    
    def _explain_vigenere(self, key: str) -> str:
        """Wyjaśnienie Szyfru Vigenere'a"""
        if not key:
            return "Brak klucza"
        key_len = len(str(key))
        return f"Każda litera przesunięta o pozycję z klucza '{key}' (długość: {key_len}) - powtarzany cyklicznie"
    
    def _explain_beaufort(self, key: str) -> str:
        """Wyjaśnienie Szyfru Beauforta"""
        if not key:
            return "Brak klucza"
        key_len = len(str(key))
        return f"Odwrotny szyfr Vigenere'a: pozycja_alfabetu = klucz - pozycja_litery"
    
    def _explain_aes(self, key_size: int = None) -> str:
        """Wyjaśnienie AES"""
        if key_size:
            return f"Szyfrowanie symetryczne AES-{key_size*8} bitów (16 rundów transformacji)"
        return "Szyfrowanie symetryczne AES z permutacją bajtów, mieszaniem kolumn i dodawaniem klucza"
    
    def _explain_rsa(self, key_size: int = None) -> str:
        """Wyjaśnienie RSA"""
        if key_size:
            return f"Szyfrowanie asymetryczne RSA-{key_size} bitów: C = M^e mod n"
        return "Szyfrowanie asymetryczne RSA: Zaszyfrowana wiadomość = (Wiadomość ^ e) mod n"
    
    def get_formatted_logs(self) -> str:
        """Zwraca sformatowane logi wszystkich operacji do wyświetlenia"""
        # Stwórz listę wszystkich operacji (historia + bieżąca)
        all_ops = self.all_operations.copy()
        if self.current_operation:
            all_ops.append(self.current_operation)
        
        if not all_ops:
            return "Brak logów. Wykonaj operację szyfrowania!"
        
        formatted = []
        formatted.append("=" * 70)
        formatted.append("HISTORIA OPERACJI")
        formatted.append("=" * 70)
        formatted.append("")
        
        # Wyświetl wszystkie operacje
        for idx, operation in enumerate(all_ops, 1):
            # Nagłówek operacji
            time_str = operation['start_time'].strftime("%d.%m.%Y %H:%M:%S")
            status = "ERROR" if operation['has_error'] else "SUCCESS"
            formatted.append(f"[{idx}] [{status}] {time_str}")
            
            # Algorytm i tryb
            header = f"    ALGORYTM: {operation['algorithm']}"
            if operation['mode']:
                header += f" | TRYB: {operation['mode']}"
            formatted.append(header)
            formatted.append("    " + "─" * 65)
            
            # Logi
            for entry in operation['logs']:
                lines = entry.format_for_display().split('\n')
                for line in lines:
                    formatted.append(f"    {line}")
            
            # Czas wykonania i wynik
            if operation['end_time']:
                duration = (operation['end_time'] - operation['start_time']).total_seconds()
                formatted.append(f"    CZAS: {duration:.3f}s")
            
            # Wynik (ukryty)
            if operation['result']:
                formatted.append(f"    WYNIK: {len(operation['result'])} znaków [ukryty]")
            
            formatted.append("")
        
        return "\n".join(formatted)
    
    def clear(self):
        """Finalizuje bieżącą operację i przygotowuje się do nowej"""
        # Zapisz bieżącą operację do historii
        if self.current_operation:
            self.all_operations.append(self.current_operation)
            self.current_operation = None
        
        # Wyczyść bieżące zmienne
        self.logs = []
        self.current_step = 0
        self.current_algorithm = None
        self.current_mode = None
        self.start_time = None
        self.end_time = None
        self.result = None
        self.has_error = False
    
    def clear_all_history(self):
        """Całkowicie czyści całą historię i bieżącą operację"""
        self.all_operations = []
        self.current_operation = None
        self.logs = []
        self.current_step = 0
        self.current_algorithm = None
        self.current_mode = None
        self.start_time = None
        self.end_time = None
        self.result = None
        self.has_error = False
    
    def get_raw_logs(self) -> List[LogEntry]:
        """Zwraca surowe wpisy logów"""
        return self.logs.copy()
    
    # ===== SZCZEGÓŁOWE LOGOWANIE ALGORYTMÓW =====
    
    def log_caesar_details(self, plaintext: str, key: int, is_encrypt: bool = True):
        """Loguje szczegóły Szyfru Cezara"""
        operation = "szyfrowanie" if is_encrypt else "deszyfrowanie"
        self.info(f"Proces {operation} Cezara", f"Przesunięcie: {key} pozycji", is_step=True)
        
        # Pokaż kilka przykładów transformacji
        samples = []
        for i, char in enumerate(plaintext[:5]):
            if char.isalpha():
                if char.isupper():
                    old_pos = ord(char) - ord('A')
                    new_pos = (old_pos + key) % 26 if is_encrypt else (old_pos - key) % 26
                    new_char = chr(ord('A') + new_pos)
                    samples.append(f"{char}({old_pos})->{new_char}({new_pos})")
                else:
                    old_pos = ord(char) - ord('a')
                    new_pos = (old_pos + key) % 26 if is_encrypt else (old_pos - key) % 26
                    new_char = chr(ord('a') + new_pos)
                    samples.append(f"{char}({old_pos})->{new_char}({new_pos})")
        
        if samples:
            self.debug("Przykłady transformacji", ", ".join(samples))
        
        # Policz znaki
        alpha_count = sum(1 for c in plaintext if c.isalpha())
        non_alpha_count = len(plaintext) - alpha_count
        self.info("Analiza tekstu", f"Litery: {alpha_count}, Znaki specjalne: {non_alpha_count}")
    
    def log_vigenere_details(self, plaintext: str, key: str, is_encrypt: bool = True):
        """Loguje szczegóły Szyfru Vigenere'a"""
        operation = "szyfrowanie" if is_encrypt else "deszyfrowanie"
        self.info(f"Proces {operation} Vigenere", f"Klucz: '{key}' (długość: {len(key)})", is_step=True)
        
        # Pokaż jak klucz się replikuje
        plaintext_alpha = ''.join(c for c in plaintext if c.isalpha()).upper()
        key_upper = key.upper()
        
        if len(plaintext_alpha) > 0:
            replicated = ""
            for i in range(min(10, len(plaintext_alpha))):
                replicated += key_upper[i % len(key_upper)]
            self.debug("Replikacja klucza", f"Dla 10 znaków: {replicated}")
        
        # Pokaż przykłady
        samples = []
        for i, char in enumerate(plaintext_alpha[:5]):
            key_shift = ord(key_upper[i % len(key_upper)]) - ord('A')
            old_pos = ord(char) - ord('A')
            new_pos = (old_pos + key_shift) % 26 if is_encrypt else (old_pos - key_shift) % 26
            new_char = chr(ord('A') + new_pos)
            samples.append(f"{char}+{key_upper[i%len(key_upper)]}({key_shift})->{new_char}")
        
        if samples:
            self.debug("Przykłady (litera + klucz -> wynik)", "; ".join(samples))
    
    def log_beaufort_details(self, plaintext: str, key: str, is_encrypt: bool = True):
        """Loguje szczegóły Szyfru Beauforta"""
        operation = "szyfrowanie" if is_encrypt else "deszyfrowanie"
        self.info(f"Proces {operation} Beauforta", f"Klucz: '{key}' (długość: {len(key)})", is_step=True)
        
        self.info("Formuła Beauforta", "C = (K - P) mod 26, gdzie K=klucz, P=plaintext", is_step=True)
        
        plaintext_alpha = ''.join(c for c in plaintext if c.isalpha()).upper()
        key_upper = key.upper()
        
        # Pokaż przykłady
        samples = []
        for i, char in enumerate(plaintext_alpha[:5]):
            key_val = ord(key_upper[i % len(key_upper)]) - ord('A')
            plain_val = ord(char) - ord('A')
            cipher_val = (key_val - plain_val) % 26
            cipher_char = chr(ord('A') + cipher_val)
            samples.append(f"({key_upper[i%len(key_upper)]}{key_val} - {char}{plain_val}) mod 26 = {cipher_char}{cipher_val}")
        
        if samples:
            self.debug("Obliczenia", samples[0])
            if len(samples) > 1:
                self.debug("Przykłady", f"... i {len(samples)-1} więcej transformacji")
    
    def log_aes_details(self, data_size: int, key_size: int = 16, is_encrypt: bool = True):
        """Loguje szczegóły AES"""
        num_rounds = {16: 10, 24: 12, 32: 14}.get(key_size, 10)
        operation = "szyfrowanie" if is_encrypt else "deszyfrowanie"
        
        self.info(f"Proces {operation} AES-{key_size*8}", f"Rundy: {num_rounds}", is_step=True)
        
        # Ile bloków
        num_blocks = (data_size + 15) // 16  # 16 bajtów na blok
        self.info("Podział na bloki", f"Liczba bloków 16-bajtowych: {num_blocks}")
        
        # Etapy
        stages = [
            "SubBytes: Substytucja bajtów przez S-Box (256 możliwych wartości)",
            "ShiftRows: Przesunięcie wierszy macierzy stanu",
            "MixColumns: Mieszanie kolumn (operacje algebraiczne w GF(2^8))",
            "AddRoundKey: Dodanie klucza rundy (XOR z kluczem)"
        ]
        
        for i, stage in enumerate(stages, 1):
            self.debug(f"Etap {i}", stage)
        
        self.info("Sekret szyfrowania", f"Transformacja wykona się {num_rounds} razy dla każdego bloku")
    
    def log_rsa_details(self, key_size: int, is_encrypt: bool = True):
        """Loguje szczegóły RSA"""
        operation = "szyfrowania" if is_encrypt else "deszyfrowania"
        
        self.info(f"Kroki {operation} RSA", f"Rozmiar modułu: {key_size} bitów", is_step=True)
        
        if is_encrypt:
            formula = "C = (M ^ e) mod n"
            explanation = "Wiadomość podniesiona do potęgi e i modulo n"
        else:
            formula = "M = (C ^ d) mod n"
            explanation = "Szyfrogram podniesiony do potęgi d i modulo n"
        
        self.info("Formuła operacji", formula)
        self.debug("Objaśnienie", explanation)
        
        self.info("Bezpieczeństwo", "RSA polega na trudności rozkładu liczby n na czynniki pierwsze p i q")
        
        # Złożoność
        estimated_bits = key_size
        self.debug("Złożoność obliczeniowa", f"~{estimated_bits}^3 operacji bitowych")
    
    def log_chacha20_details(self, data_size: int, key_size: int = 32, is_encrypt: bool = True):
        """Loguje szczegóły ChaCha20"""
        operation = "szyfrowania" if is_encrypt else "deszyfrowania"
        
        self.info(f"Kroki {operation} ChaCha20", f"Rozmiar klucza: {key_size*8} bitów", is_step=True)
        
        # Ile bloków
        num_blocks = (data_size + 63) // 64  # 64 bajty na blok ChaCha20
        self.info("Podział na bloki", f"Liczba bloków 64-bajtowych: {num_blocks}")
        
        self.info("Algorytm", "ChaCha20 - szyfrowanie strumieniowe")
        self.debug("Kroki na blok", "20 rund (stąd nazwa: ChaCha20)")
        self.debug("Operacje", "Dodawanie modulo 2^32 + rotacja + XOR (ARX)")

