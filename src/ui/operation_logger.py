"""
System logowania dla operacji kryptograficznych
"""

from typing import List, Optional
from enum import Enum


class LogLevel(Enum):
    """Poziomy logowania"""
    INFO = "INFO"
    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    ERROR = "ERROR"
    DEBUG = "DEBUG"


class LogEntry:
    """Pojedynczy wpis logu"""
    
    def __init__(self, level: LogLevel, message: str, details: Optional[str] = None):
        self.level = level
        self.message = message
        self.details = details
        
    def format_for_display(self) -> str:
        """Formatuje wpis do wyświetlenia"""
        # Ikony na podstawie poziomu
        icons = {
            LogLevel.INFO: "?",
            LogLevel.SUCCESS: "✓",
            LogLevel.WARNING: "⚠️",
            LogLevel.ERROR: "x",
            LogLevel.DEBUG: ""
        }
        
        icon = icons.get(self.level, "•")
        formatted = f"{icon} {self.message}"
        
        if self.details:
            formatted += f"\n   └─ {self.details}"
        
        return formatted


class OperationLogger:
    """Logger dla operacji kryptograficznych"""
    
    def __init__(self):
        self.logs: List[LogEntry] = []
        self.current_algorithm: Optional[str] = None
        self.current_mode: Optional[str] = None
    
    def add_log(self, level: LogLevel, message: str, details: Optional[str] = None):
        """Dodaje wpis do logu"""
        entry = LogEntry(level, message, details)
        self.logs.append(entry)
        return entry
    
    def info(self, message: str, details: Optional[str] = None):
        """Dodaje log INFO"""
        return self.add_log(LogLevel.INFO, message, details)
    
    def success(self, message: str, details: Optional[str] = None):
        """Dodaje log SUCCESS"""
        return self.add_log(LogLevel.SUCCESS, message, details)
    
    def warning(self, message: str, details: Optional[str] = None):
        """Dodaje log WARNING"""
        return self.add_log(LogLevel.WARNING, message, details)
    
    def error(self, message: str, details: Optional[str] = None):
        """Dodaje log ERROR"""
        return self.add_log(LogLevel.ERROR, message, details)
    
    def debug(self, message: str, details: Optional[str] = None):
        """Dodaje log DEBUG"""
        return self.add_log(LogLevel.DEBUG, message, details)
    
    def set_algorithm(self, algorithm: str, mode: Optional[str] = None):
        """Ustawia aktualny algorytm i tryb"""
        self.current_algorithm = algorithm
        self.current_mode = mode
    
    def get_formatted_logs(self) -> str:
        """Zwraca sformatowane logi do wyświetlenia"""
        if not self.logs:
            return "Brak logów. Wykonaj operację szyfrowania!"
        
        formatted = []
        
        # Dodaj nagłówek z informacją o algorytmie
        if self.current_algorithm:
            header = f"ALGORYTM: {self.current_algorithm}"
            if self.current_mode:
                header += f" | TRYB: {self.current_mode}"
            formatted.append(header)
            formatted.append("─" * 60)
        
        for i, entry in enumerate(self.logs, 1):
            formatted.append(entry.format_for_display())
        
        return "\n".join(formatted)
    
    def clear(self):
        """Czyści logi"""
        self.logs.clear()
    
    def get_raw_logs(self) -> List[LogEntry]:
        """Zwraca surowe wpisy logów"""
        return self.logs.copy()
