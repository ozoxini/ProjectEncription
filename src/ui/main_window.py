"""
Główne okno aplikacji kryptograficznej
"""

from tkinter import EW
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QStackedWidget, QLabel, QPushButton, QTextEdit, 
                            QLineEdit, QComboBox, QSpinBox, QFileDialog, 
                            QMessageBox, QGroupBox, QFormLayout, QSplitter, QScrollArea)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
import os
import ast

from ..crypto.algorithm_manager import AlgorithmManager
from .operation_logger import OperationLogger
from ..crypto.ecdh_key_exchange import ECDHKeyExchange


class MainWindow(QMainWindow):
    """Główne okno aplikacji"""
    
    def __init__(self):
        super().__init__()
        self.algorithm_manager = AlgorithmManager()
        self.current_algorithm = None
        self.logger = OperationLogger()  # Logger do śledzenia operacji
        self.ecdh = ECDHKeyExchange()  # Instancja ECDH
        self.ecdh_keypair = None  # Przechowuje wygenerowaną parę
        self.ecdh_shared_secret = None  # Przechowuje wspólny sekret

        # Kontrolki specyficzne dla RSA (przeniesione z init_ui)
        self.rsa_group_box = QGroupBox("Opcje RSA")
        rsa_outer_layout = QFormLayout(self.rsa_group_box)
        
        self.generate_keys_btn = QPushButton("Generuj nowe klucze")
        rsa_outer_layout.addRow(self.generate_keys_btn)

        self.rsa_mode_combo = QComboBox()
        self.rsa_mode_combo.addItems(["Szyfruj / Deszyfruj", "Podpisz / Weryfikuj"])
        rsa_outer_layout.addRow("Tryb operacji:", self.rsa_mode_combo)

        keys_layout = QHBoxLayout()
        
        public_key_layout = QVBoxLayout()
        public_key_label = QLabel("Klucz publiczny:")
        self.public_key_text = QTextEdit()
        self.public_key_text.setPlaceholderText("(e, n)")
        self.public_key_text.setMaximumHeight(60)
        public_key_layout.addWidget(public_key_label)
        public_key_layout.addWidget(self.public_key_text)
        
        private_key_layout = QVBoxLayout()
        private_key_label = QLabel("Klucz prywatny:")
        self.private_key_text = QTextEdit()
        self.private_key_text.setPlaceholderText("(d, n)")
        self.private_key_text.setMaximumHeight(60)
        private_key_layout.addWidget(private_key_label)
        private_key_layout.addWidget(self.private_key_text)
        
        keys_layout.addLayout(public_key_layout)
        keys_layout.addLayout(private_key_layout)
        rsa_outer_layout.addRow(keys_layout)

        self.init_ui()
        self.apply_studio_style()
    
    def init_ui(self):
        """Inicjalizuje interfejs użytkownika w stylu Studio"""
        self.setWindowTitle("Szyfronator")
        self.setGeometry(100, 100, 850, 750)
        
        # Główny widget i layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(35, 25, 35, 25)
        main_layout.setAlignment(Qt.AlignTop)
        
        # Duży tytuł aplikacji, wyrównany do lewej
        title_label = QLabel("Szyfronator")
        title_label.setObjectName("mainTitle")
        title_label.setAlignment(Qt.AlignLeft)
        main_layout.addWidget(title_label)
        
        # Segmented Control (przełącznik widoków), wyrównany do lewej
        segmented_control_layout = QHBoxLayout()
        segmented_control_layout.setSpacing(6)
        segmented_control_layout.setAlignment(Qt.AlignLeft)

        self.btn_tekst = QPushButton("Tekst")
        self.btn_tekst.setObjectName("segmentedButtonLeft")
        self.btn_tekst.setCheckable(True)
        
        self.btn_plik = QPushButton("Plik")
        self.btn_plik.setObjectName("segmentedButtonMiddle")
        self.btn_plik.setCheckable(True)
        
        self.btn_logi = QPushButton("Logi")
        self.btn_logi.setObjectName("segmentedButtonMiddle")
        self.btn_logi.setCheckable(True)
        
        self.btn_wymiana_kluczy = QPushButton("Wymiana Kluczy")
        self.btn_wymiana_kluczy.setObjectName("segmentedButtonRight")
        self.btn_wymiana_kluczy.setCheckable(True)
        
        segmented_control_layout.addWidget(self.btn_tekst)
        segmented_control_layout.addWidget(self.btn_plik)
        segmented_control_layout.addWidget(self.btn_logi)
        segmented_control_layout.addWidget(self.btn_wymiana_kluczy)
        segmented_control_layout.addStretch(1)
        main_layout.addLayout(segmented_control_layout)
        
        # Kontener na przełączane widoki
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.addWidget(self.create_text_view())
        self.stacked_widget.addWidget(self.create_file_view())
        self.stacked_widget.addWidget(self.create_logs_view())
        self.stacked_widget.addWidget(self.create_ecdh_view())
        main_layout.addWidget(self.stacked_widget)
        
        # Połączenia sygnałów
        self.btn_tekst.clicked.connect(lambda: self.switch_view(0))
        self.btn_plik.clicked.connect(lambda: self.switch_view(1))
        self.btn_logi.clicked.connect(lambda: self.switch_view(2))
        self.btn_wymiana_kluczy.clicked.connect(lambda: self.switch_view(3))
        
        # Połączenia przycisków
        self.generate_keys_btn.clicked.connect(self.generate_rsa_keys)
        self.encrypt_btn.clicked.connect(self.encrypt_text)
        self.decrypt_btn.clicked.connect(self.decrypt_text)
        self.clear_btn.clicked.connect(self.clear_text)
        self.encrypt_file_btn.clicked.connect(self.encrypt_file)
        self.decrypt_file_btn.clicked.connect(self.decrypt_file)
        
        # Pasek statusu
        self.statusBar().showMessage("Gotowy")
        version_label = QLabel("v.1.5a")
        version_label.setObjectName("versionLabel")
        self.statusBar().addPermanentWidget(version_label)
        
        # Ustawienie stanu początkowego
        self.switch_view(0)
        if self.algorithm_combo.count() > 0:
            self.on_algorithm_changed(self.algorithm_combo.currentText())

    def switch_view(self, index):
        """Przełącza widok i styl przycisków"""
        self.stacked_widget.setCurrentIndex(index)
        self.btn_tekst.setChecked(index == 0)
        self.btn_plik.setChecked(index == 1)
        self.btn_logi.setChecked(index == 2)
        self.btn_wymiana_kluczy.setChecked(index == 3)
        
        # Odśwież logi gdy przełączysz na zakładkę Logi
        if index == 2:
            self.refresh_logs_view()
        
        # Odśwież ECDH gdy przełączysz na zakładkę Wymiana Kluczy
        if index == 3:
            self.refresh_ecdh_view()

    def create_text_view(self):
        """Tworzy widok ("kartę") do szyfrowania tekstu"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setSpacing(15)
        layout.setContentsMargins(0, 20, 0, 0)
        layout.setAlignment(Qt.AlignTop)
        
        # Karta z ustawieniami
        control_card = QGroupBox()
        control_layout = QFormLayout(control_card)
        control_layout.setSpacing(15)
        
        self.algorithm_combo = QComboBox()
        self.populate_algorithms()
        self.algorithm_combo.currentTextChanged.connect(self.on_algorithm_changed)
        control_layout.addRow("Algorytm:", self.algorithm_combo)

        # Dodajemy ComboBox dla rozmiaru klucza AES, początkowo ukryty
        self.aes_key_size_combo = QComboBox()
        self.aes_key_size_combo.addItems(["AES-128 (16 bajtów)", "AES-192 (24 bajty)", "AES-256 (32 bajty)"])
        self.aes_key_size_label = QLabel("Rozmiar klucza AES:")
        control_layout.addRow(self.aes_key_size_label, self.aes_key_size_combo)
        self.aes_key_size_label.hide()
        self.aes_key_size_combo.hide()
        
        control_layout.addRow(self.rsa_group_box) # Dodajemy rsa_group_box do layoutu tekstowego
        # self.rsa_group_box.hide() # Ukrywanie jest obsługiwane przez on_algorithm_changed
        
        # ZAMIANA: zamiast pojedynczego QSpinBox udostępniamy stos (spin/text)
        self.key_spin = QSpinBox()
        self.key_spin.setRange(-25, 25)
        self.key_spin.setValue(3)
        spin_container = QWidget()
        spin_layout = QHBoxLayout(spin_container)
        spin_layout.setContentsMargins(0, 0, 0, 0)
        spin_layout.addWidget(self.key_spin)

        self.key_text = QLineEdit()
        self.key_text.setPlaceholderText("Wpisz klucz tekstowy...")
        text_container = QWidget()
        text_layout = QHBoxLayout(text_container)
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.addWidget(self.key_text)

        self.key_stack = QStackedWidget()
        self.key_stack.addWidget(spin_container)   # index 0 -> numeric
        self.key_stack.addWidget(text_container)   # index 1 -> text

        control_layout.addRow(self.key_stack)
        ##self.key_input = QTextEdit()
        ##control_layout.addRow("Klucz:", self.input_text)

        layout.addWidget(control_card)

        # Karta z polami tekstowymi
        text_card = QGroupBox()
        text_layout = QVBoxLayout(text_card)
        text_layout.setSpacing(15)
        
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Wpisz lub wklej tekst...")
        self.output_text = QTextEdit()
        self.output_text.setPlaceholderText("Tutaj pojawi się wynik...")
        self.output_text.setReadOnly(True)
        
        text_layout.addWidget(self.input_text)
        text_layout.addWidget(self.output_text)
        layout.addWidget(text_card)

        # Przyciski akcji
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        self.encrypt_btn = QPushButton("Szyfruj")
        self.decrypt_btn = QPushButton("Deszyfruj")
        self.clear_btn = QPushButton("Wyczyść")
        self.clear_btn.setObjectName("clearButton")

        button_layout.addStretch()
        button_layout.addWidget(self.encrypt_btn)
        button_layout.addWidget(self.decrypt_btn)
        button_layout.addWidget(self.clear_btn)
        layout.addLayout(button_layout)
        
        layout.addStretch(1)
        return view

    def create_file_view(self):
        """Tworzy widok ("kartę") do szyfrowania plików"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setSpacing(15)
        layout.setContentsMargins(0, 20, 0, 0)
        layout.setAlignment(Qt.AlignTop)

        # Karta z ustawieniami
        settings_card = QGroupBox()
        settings_layout = QFormLayout(settings_card)
        settings_layout.setSpacing(15)
        
        self.file_algorithm_combo = QComboBox()
        self.populate_file_algorithms()
        # podłączamy także zmianę wyboru w combo plików do tej samej metody
        self.file_algorithm_combo.currentTextChanged.connect(self.on_algorithm_changed)
        settings_layout.addRow("Algorytm:", self.file_algorithm_combo)

        # Dodajemy ComboBox dla rozmiaru klucza AES w widoku pliku
        self.file_aes_key_size_combo = QComboBox()
        self.file_aes_key_size_combo.addItems(["AES-128 (16 bajtów)", "AES-192 (24 bajty)", "AES-256 (32 bajty)"])
        self.file_aes_key_size_label = QLabel("Rozmiar klucza AES:")
        settings_layout.addRow(self.file_aes_key_size_label, self.file_aes_key_size_combo)
        self.file_aes_key_size_label.hide()
        self.file_aes_key_size_combo.hide()

        settings_layout.addRow(self.rsa_group_box) # Dodajemy rsa_group_box do layoutu plikowego
        # self.rsa_group_box.hide() # Ukrywanie jest obsługiwane przez on_algorithm_changed
        
        # ZAMIANA podobnie jak w widoku tekstowym: stack dla klucza plikowego
        self.file_key_spin = QSpinBox()
        self.file_key_spin.setRange(-25, 25)
        self.file_key_spin.setValue(3)
        fspin_container = QWidget()
        fspin_layout = QHBoxLayout(fspin_container)
        fspin_layout.setContentsMargins(0, 0, 0, 0)
        fspin_layout.addWidget(self.file_key_spin)

        self.file_key_text = QLineEdit()
        self.file_key_text.setPlaceholderText("Wpisz klucz tekstowy...")
        ftext_container = QWidget()
        ftext_layout = QHBoxLayout(ftext_container)
        ftext_layout.setContentsMargins(0, 0, 0, 0)
        ftext_layout.addWidget(self.file_key_text)


        self.file_key_stack = QStackedWidget()
        self.file_key_stack.addWidget(fspin_container)
        self.file_key_stack.addWidget(ftext_container)


        settings_layout.addRow(self.file_key_stack)
        layout.addWidget(settings_card)
        
        # Karta operacji na pliku
        file_card = QGroupBox()
        file_layout = QVBoxLayout(file_card)
        file_layout.setSpacing(15)
        
        file_selection_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Wybierz plik do przetworzenia...")
        self.file_path_input.setReadOnly(True)
        self.browse_btn = QPushButton("...")
        self.browse_btn.setFixedWidth(50)
        self.browse_btn.clicked.connect(self.browse_file)
        
        file_selection_layout.addWidget(self.file_path_input)
        file_selection_layout.addWidget(self.browse_btn)
        file_layout.addLayout(file_selection_layout)
        
        button_layout = QHBoxLayout()
        self.encrypt_file_btn = QPushButton("Szyfruj Plik")
        self.decrypt_file_btn = QPushButton("Deszyfruj Plik")
        
        button_layout.addStretch()
        button_layout.addWidget(self.encrypt_file_btn)
        button_layout.addWidget(self.decrypt_file_btn)
        file_layout.addLayout(button_layout)
        
        layout.addWidget(file_card)
        
        layout.addStretch(1)
        return view

    def create_logs_view(self):
        """Tworzy widok ("kartę") do wyświetlania logów"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setSpacing(15)
        layout.setContentsMargins(0, 20, 0, 0)
        
        # Tytuł sekcji
        logs_title = QLabel("Historia operacji")
        logs_title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        layout.addWidget(logs_title)
        
        # Główny obszar logów
        logs_card = QGroupBox()
        logs_layout = QVBoxLayout(logs_card)
        logs_layout.setSpacing(10)
        
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        self.logs_text.setFont(QFont("Courier New", 10))
        self.logs_text.setPlaceholderText("Logi operacji będą wyświetlane tutaj.\nWykonaj szyfrowanie, aby zobaczyć szczegóły.")
        logs_layout.addWidget(self.logs_text)
        
        layout.addWidget(logs_card)
        
        # Przycisk do czyszczenia logów
        button_layout = QHBoxLayout()
        
        clear_logs_btn = QPushButton("Wyczyść logi")
        clear_logs_btn.setObjectName("secondaryButton")
        clear_logs_btn.clicked.connect(self.clear_logs)
        button_layout.addWidget(clear_logs_btn)
        
        export_logs_btn = QPushButton("Eksportuj logi (txt)")
        export_logs_btn.setObjectName("secondaryButton")
        export_logs_btn.clicked.connect(self.export_logs)
        button_layout.addWidget(export_logs_btn)
        
        button_layout.addStretch(1)
        layout.addLayout(button_layout)
        
        layout.addStretch(1)
        
        return view

    def refresh_logs_view(self):
        """Odświeża widok logów"""
        if hasattr(self, 'logs_text'):
            self.logs_text.setPlainText(self.logger.get_formatted_logs())
    
    def clear_logs(self):
        """Czyści wszystkie logi"""
        self.logger.clear_all_history()
        self.refresh_logs_view()
        QMessageBox.information(self, "Info", "Wszystkie logi zostały wyczyszczone.")
    
    def export_logs(self):
        """Eksportuje logi do pliku tekstowego"""
        if not self.logger.get_raw_logs():
            QMessageBox.warning(self, "Info", "Brak logów do eksportu!")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Eksportuj logi", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.logger.get_formatted_logs())
                QMessageBox.information(self, "Sukces", f"Logi wyeksportowane do:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Błąd", f"Błąd eksportu logów:\n{str(e)}")

    def create_ecdh_view(self):
        """Tworzy widok do wymiany kluczy ECDH"""
        # ScrollArea dla całej karty
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_widget = QWidget()
        layout = QVBoxLayout(scroll_widget)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 20, 0, 0)
        
       
        
        # --- SEKCJA 1: Generacja Pary Kluczy ---
        section1_title = QLabel("1. Moja Para Kluczy")
        section1_title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        layout.addWidget(section1_title)
        
        section1_card = QGroupBox()
        section1_layout = QVBoxLayout(section1_card)
        section1_layout.setSpacing(8)
        
        self.ecdh_generate_btn = QPushButton("Generuj Nową Parę Kluczy")
        self.ecdh_generate_btn.setObjectName("primaryButton")
        self.ecdh_generate_btn.clicked.connect(self.generate_ecdh_keypair)
        section1_layout.addWidget(self.ecdh_generate_btn)
        
        # Wiersz: Klucz publiczny
        pub_label = QLabel("Klucz publiczny (Base64):")
        pub_label.setFont(QFont("Segoe UI", 9))
        self.ecdh_public_key_text = QTextEdit()
        self.ecdh_public_key_text.setMaximumHeight(60)
        self.ecdh_public_key_text.setFont(QFont("Courier New", 8))
        self.ecdh_public_key_text.setPlaceholderText("Wciśnij 'Generuj Nową Parę Kluczy' aby wyświetlić (lub wklej tutaj dla testu)")
        section1_layout.addWidget(pub_label)
        section1_layout.addWidget(self.ecdh_public_key_text)
        
        pub_copy_btn = QPushButton("Skopiuj Klucz Publiczny")
        pub_copy_btn.setObjectName("secondaryButton")
        pub_copy_btn.clicked.connect(lambda: self.copy_to_clipboard(self.ecdh_public_key_text.toPlainText(), "Klucz publiczny"))
        section1_layout.addWidget(pub_copy_btn)
        
        # Wiersz: Klucz prywatny
        priv_label = QLabel("Klucz prywatny (HEX) - PRZECHOWUJ W TAJNOŚCI:")
        priv_label.setFont(QFont("Segoe UI", 9))
        self.ecdh_private_key_text = QTextEdit()
        self.ecdh_private_key_text.setMaximumHeight(60)
        self.ecdh_private_key_text.setFont(QFont("Courier New", 8))
        self.ecdh_private_key_text.setPlaceholderText("Wyświetlony tutaj - NIGDY nie udostępniaj! (edytowalne do testów)")
        section1_layout.addWidget(priv_label)
        section1_layout.addWidget(self.ecdh_private_key_text)
        
        layout.addWidget(section1_card)
        
        # --- SEKCJA 2: Klucz Drugiej Osoby ---
        section2_title = QLabel("2. Klucz Publiczny Drugiej Osoby")
        section2_title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        layout.addWidget(section2_title)
        
        section2_info = QLabel(
            "Każdy publiczny klucz jest INNY (bo zawiera inny losowy punkt na krzywej). "
            "To jest normalne i bezpieczne! Wklej klucz drugiej osoby poniżej."
        )
        section2_info.setFont(QFont("Segoe UI", 8))
        section2_info.setStyleSheet("color: #aaaaaa;")
        section2_info.setWordWrap(True)
        layout.addWidget(section2_info)
        
        section2_card = QGroupBox()
        section2_layout = QVBoxLayout(section2_card)
        section2_layout.setSpacing(8)
        
        their_pub_label = QLabel("Wklej tutaj klucz publiczny drugiej osoby (Base64):")
        their_pub_label.setFont(QFont("Segoe UI", 9))
        self.ecdh_their_public_text = QTextEdit()
        self.ecdh_their_public_text.setMaximumHeight(60)
        self.ecdh_their_public_text.setFont(QFont("Courier New", 8))
        self.ecdh_their_public_text.setPlaceholderText("Paste Base64 encoded public key here...")
        section2_layout.addWidget(their_pub_label)
        section2_layout.addWidget(self.ecdh_their_public_text)
        
        self.ecdh_calculate_secret_btn = QPushButton("Oblicz Wspólny Sekret")
        self.ecdh_calculate_secret_btn.setObjectName("primaryButton")
        self.ecdh_calculate_secret_btn.clicked.connect(self.calculate_ecdh_secret)
        section2_layout.addWidget(self.ecdh_calculate_secret_btn)
        
        layout.addWidget(section2_card)
        
        # --- SEKCJA 3: Szyfrowanie Wiadomości ---
        section3_title = QLabel("3. Szyfruj Wiadomość")
        section3_title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        layout.addWidget(section3_title)
        
        section3_card = QGroupBox()
        section3_layout = QVBoxLayout(section3_card)
        section3_layout.setSpacing(8)
        
        plaintext_label = QLabel("Wiadomość do zaszyfrowania:")
        plaintext_label.setFont(QFont("Segoe UI", 9))
        self.ecdh_plaintext_input = QTextEdit()
        self.ecdh_plaintext_input.setMaximumHeight(60)
        self.ecdh_plaintext_input.setPlaceholderText("Wpisz wiadomość...")
        section3_layout.addWidget(plaintext_label)
        section3_layout.addWidget(self.ecdh_plaintext_input)
        
        self.ecdh_encrypt_btn = QPushButton("Zaszyfruj")
        self.ecdh_encrypt_btn.setObjectName("primaryButton")
        self.ecdh_encrypt_btn.clicked.connect(self.encrypt_ecdh_message)
        section3_layout.addWidget(self.ecdh_encrypt_btn)
        
        ciphertext_label = QLabel("Zaszyfrowana wiadomość (Base64):")
        ciphertext_label.setFont(QFont("Segoe UI", 9))
        self.ecdh_ciphertext_output = QTextEdit()
        self.ecdh_ciphertext_output.setReadOnly(True)
        self.ecdh_ciphertext_output.setMaximumHeight(60)
        self.ecdh_ciphertext_output.setFont(QFont("Courier New", 8))
        self.ecdh_ciphertext_output.setPlaceholderText("Będzie wyświetlona tutaj po szyfrowaniu")
        section3_layout.addWidget(ciphertext_label)
        section3_layout.addWidget(self.ecdh_ciphertext_output)
        
        cipher_copy_btn = QPushButton("Skopiuj Zaszyfrowaną Wiadomość")
        cipher_copy_btn.setObjectName("secondaryButton")
        cipher_copy_btn.clicked.connect(lambda: self.copy_to_clipboard(self.ecdh_ciphertext_output.toPlainText(), "Zaszyfrowana wiadomość"))
        section3_layout.addWidget(cipher_copy_btn)
        
        layout.addWidget(section3_card)
        
        # --- SEKCJA 4: Deszyfrowanie Wiadomości ---
        section4_title = QLabel("4. Deszyfruj Wiadomość")
        section4_title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        layout.addWidget(section4_title)
        
        section4_card = QGroupBox()
        section4_layout = QVBoxLayout(section4_card)
        section4_layout.setSpacing(8)
        
        encrypted_label = QLabel("Zaszyfrowana wiadomość od drugiej osoby (Base64):")
        encrypted_label.setFont(QFont("Segoe UI", 9))
        self.ecdh_encrypted_input = QTextEdit()
        self.ecdh_encrypted_input.setMaximumHeight(60)
        self.ecdh_encrypted_input.setFont(QFont("Courier New", 8))
        self.ecdh_encrypted_input.setPlaceholderText("Paste encrypted message here...")
        section4_layout.addWidget(encrypted_label)
        section4_layout.addWidget(self.ecdh_encrypted_input)
        
        self.ecdh_decrypt_btn = QPushButton("Deszyfruj")
        self.ecdh_decrypt_btn.setObjectName("primaryButton")
        self.ecdh_decrypt_btn.clicked.connect(self.decrypt_ecdh_message)
        section4_layout.addWidget(self.ecdh_decrypt_btn)
        
        decrypted_label = QLabel("Odszyfrowana wiadomość:")
        decrypted_label.setFont(QFont("Segoe UI", 9))
        self.ecdh_decrypted_output = QTextEdit()
        self.ecdh_decrypted_output.setReadOnly(True)
        self.ecdh_decrypted_output.setMaximumHeight(60)
        self.ecdh_decrypted_output.setFont(QFont("Courier New", 8))
        self.ecdh_decrypted_output.setPlaceholderText("Będzie wyświetlona tutaj po deszyfrowaniu")
        section4_layout.addWidget(decrypted_label)
        section4_layout.addWidget(self.ecdh_decrypted_output)
        
        layout.addWidget(section4_card)
        
        # Status info
        self.ecdh_status_label = QLabel("Status: Gotowy do generacji pary kluczy")
        self.ecdh_status_label.setFont(QFont("Segoe UI", 8))
        self.ecdh_status_label.setStyleSheet("color: #888888;")
        layout.addWidget(self.ecdh_status_label)
        
        layout.addStretch(1)
        scroll_area.setWidget(scroll_widget)
        return scroll_area

    def refresh_ecdh_view(self):
        """Odświeża widok ECDH"""
        pass

    def copy_to_clipboard(self, text, label="Tekst"):
        """Kopiuje tekst do schowka"""
        if not text:
            QMessageBox.warning(self, "Info", f"Brak zawartości do skopiowania!")
            return
        
        from PyQt5.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        self.ecdh_status_label.setText(f"✓ {label} skopiowany do schowka")

    def generate_ecdh_keypair(self):
        """Generuje nową parę kluczy ECDH"""
        try:
            self.logger.clear()
            self.logger.set_algorithm("ECDH", None)
            self.logger.info("Generacja pary kluczy ECDH", "Rozpoczęcie", is_step=True)
            
            # Generuj parę
            keypair = self.ecdh.generate_keypair()
            self.ecdh_keypair = keypair
            
            # Wyświetl klucze
            self.ecdh_public_key_text.setPlainText(keypair['public_key_b64'])
            self.ecdh_private_key_text.setPlainText(keypair['private_key_hex'])
            
            self.logger.success("Klucz publiczny", keypair['public_key_b64'][:40] + "...", is_step=True)
            self.logger.debug("Klucz prywatny (HEX)", keypair['private_key_hex'][:40] + "...")
            self.logger.log_ecdh_details("Generacja pary")
            
            self.ecdh_status_label.setText("✓ Para kluczy wygenerowana! Teraz podziel się kluczem publicznym.")
            QMessageBox.information(self, "Sukces", "Para kluczy wygenerowana.\n\nPodziel się swoim kluczem publicznym z drugą osobą!")
            
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd podczas generacji pary:\n{str(e)}")
            self.ecdh_status_label.setText(f"✗ Błąd: {str(e)}")

    def calculate_ecdh_secret(self):
        """Oblicza wspólny sekret ECDH"""
        try:
            if not self.ecdh_keypair:
                QMessageBox.warning(self, "Info", "Najpierw generuj swoją parę kluczy!")
                return
            
            their_public_b64 = self.ecdh_their_public_text.toPlainText().strip()
            if not their_public_b64:
                QMessageBox.warning(self, "Info", "Wklej klucz publiczny drugiej osoby!")
                return
            
            self.logger.clear()
            self.logger.set_algorithm("ECDH", None)
            self.logger.info("Obliczanie wspólnego sekretu", "Rozpoczęcie", is_step=True)
            
            # Oblicz sekret
            shared_secret = self.ecdh.compute_shared_secret(
                self.ecdh_keypair['private_key_int'],
                their_public_b64
            )
            self.ecdh_shared_secret = shared_secret
            
            self.logger.success("Wspólny sekret", shared_secret.hex()[:40] + "...", is_step=True)
            self.logger.debug("Rozmiar sekretu (bajty)", str(len(shared_secret)))
            self.logger.log_ecdh_details("Wspólny sekret")
            
            self.ecdh_status_label.setText("✓ Wspólny sekret obliczony! Możesz teraz szyfrować wiadomości.")
            QMessageBox.information(
                self, 
                "Sukces", 
                "✓ Wspólny sekret obliczony!\n\n"
                "Twój sekret (hex):\n" + shared_secret.hex()[:60] + "...\n\n"
                "WAŻNE: Druga osoba powinna mieć IDENTYCZNY sekret!\n"
                "Jeśli sekrety się nie zgadzają, coś poszło nie tak.\n\n"
                "Możesz teraz szyfrować i deszyfrować wiadomości."
            )
            
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd podczas obliczania sekretu:\n{str(e)}")
            self.ecdh_status_label.setText(f"✗ Błąd: {str(e)}")

    def encrypt_ecdh_message(self):
        """Szyfruje wiadomość za pomocą wspólnego sekretu ECDH"""
        try:
            if not self.ecdh_shared_secret:
                QMessageBox.warning(self, "Info", "Najpierw oblicz wspólny sekret!")
                return
            
            plaintext = self.ecdh_plaintext_input.toPlainText()
            if not plaintext:
                QMessageBox.warning(self, "Info", "Wpisz wiadomość do zaszyfrowania!")
                return
            
            self.logger.clear()
            self.logger.set_algorithm("ECDH", None)
            self.logger.info("Szyfrowanie wiadomości", f"Rozmiar: {len(plaintext)} znaków", is_step=True)
            
            # Szyfruj
            ciphertext_b64 = self.ecdh.encrypt_message(plaintext, self.ecdh_shared_secret)
            
            self.ecdh_ciphertext_output.setPlainText(ciphertext_b64)
            
            self.logger.success("Wiadomość zaszyfrowana", ciphertext_b64[:40] + "...", is_step=True)
            self.logger.debug("Rozmiar zaszyfrowany (Base64)", str(len(ciphertext_b64)))
            self.logger.log_ecdh_details("Szyfrowanie")
            
            self.ecdh_status_label.setText("✓ Wiadomość zaszyfrowana! Skopiuj i wyślij drugiej osobie.")
            
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd podczas szyfrowania:\n{str(e)}")
            self.ecdh_status_label.setText(f"✗ Błąd: {str(e)}")

    def decrypt_ecdh_message(self):
        """Deszyfruje wiadomość za pomocą wspólnego sekretu ECDH"""
        try:
            if not self.ecdh_shared_secret:
                QMessageBox.warning(self, "Info", "Najpierw oblicz wspólny sekret!")
                return
            
            ciphertext_b64 = self.ecdh_encrypted_input.toPlainText().strip()
            if not ciphertext_b64:
                QMessageBox.warning(self, "Info", "Wklej zaszyfrowaną wiadomość!")
                return
            
            self.logger.clear()
            self.logger.set_algorithm("ECDH", None)
            self.logger.info("Deszyfrowanie wiadomości", "Rozpoczęcie", is_step=True)
            
            # Deszyfruj
            plaintext = self.ecdh.decrypt_message(ciphertext_b64, self.ecdh_shared_secret)
            
            self.ecdh_decrypted_output.setPlainText(plaintext)
            
            self.logger.success("Wiadomość odszyfrowana", f"{len(plaintext)} znaków", is_step=True)
            self.logger.info("Treść", plaintext)
            self.logger.log_ecdh_details("Deszyfrowanie")
            
            self.ecdh_status_label.setText("✓ Wiadomość odszyfrowana!")
            
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Błąd podczas deszyfrowania:\n{str(e)}")
            self.ecdh_status_label.setText(f"✗ Błąd: {str(e)}")

    def apply_studio_style(self):
        """Aplikuje profesjonalny, stonowany styl 'Studio UI'"""
        # --- Paleta Kolorów ---
        BG_COLOR = "#1a1a1f"           # Głęboki grafit
        CARD_COLOR = "#25252b"         # Ciemnoszara karta
        INPUT_COLOR = "#2d2d33"        # Pole wprowadzania
        BORDER_COLOR = "#3a3a40"       # Subtelna ramka
        TEXT_PRIMARY = "#ffffff"       # Czysty, jasny tekst
        TEXT_SECONDARY = "#a0a0a8"     # Drugorzędny szary
        ACCENT_BLUE = "#4a90e2"        # Niebieski
        ACCENT_GREEN = "#2ecc71"       # Zielony
        ACCENT_RED = "#e74c3c"         # Czerwony

        self.setStyleSheet(f"""
            QWidget {{
                background-color: {BG_COLOR};
                color: {TEXT_PRIMARY};
                font-family: 'Segoe UI', 'Helvetica Neue', sans-serif;
                font-size: 11pt;
            }}
            QLabel {{
                background-color: transparent;
                padding-top: 8px;
            }}
            #mainTitle {{
                font-size: 30pt;
                font-weight: 600;
                padding-bottom: 15px;
            }}
            QGroupBox {{
                background-color: {CARD_COLOR};
                border: none;
                border-radius: 12px;
                padding: 20px;
            }}
            QGroupBox::title {{
                color: {TEXT_SECONDARY};
                font-size: 10pt;
                font-weight: bold;
                padding-left: 0px;
                padding-bottom: 5px;
            }}
            #segmentedButtonLeft, #segmentedButtonMiddle, #segmentedButtonRight {{
                background-color: transparent;
                border: 1px solid {BORDER_COLOR};
                padding: 8px 30px;
                font-size: 11pt;
                font-weight: 500;
                color: {TEXT_SECONDARY};
            }}
            #segmentedButtonLeft {{
                border-top-left-radius: 8px;
                border-bottom-left-radius: 8px;
            }}
            #segmentedButtonMiddle {{
                border-radius: 8px;
                margin-left: 0px;
                margin-right: 0px;
            }}
            #segmentedButtonRight {{
                border-top-right-radius: 8px;
                border-bottom-right-radius: 8px;
                margin-left: 0px;
            }}
            #segmentedButtonLeft:checked, #segmentedButtonMiddle:checked, #segmentedButtonRight:checked {{
                background-color: {INPUT_COLOR};
                color: {TEXT_PRIMARY};
                border-color: {INPUT_COLOR};
            }}
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {ACCENT_BLUE}, stop:1 #3a7bd5);
                color: {TEXT_PRIMARY};
                border: none;
                border-radius: 10px;
                padding: 14px 28px;
                font-size: 12pt;
                font-weight: 600;
                min-height: 20px;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #5ba0f2, stop:1 #4a8bd5);
            }}
            QPushButton:pressed {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3a7bd5, stop:1 #2e6bc4);
            }}
            #clearButton {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {ACCENT_RED}, stop:1 #c0392b);
            }}
            #clearButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #e55a4a, stop:1 #d63031);
            }}
            #browse_btn {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {INPUT_COLOR}, stop:1 #25252b);
                padding: 8px 16px;
                font-size: 11pt;
            }}
            QTextEdit, QLineEdit, QComboBox, QSpinBox {{
                background-color: {INPUT_COLOR};
                border: 1px solid {BORDER_COLOR};
                border-radius: 8px;
                padding: 12px;
                color: {TEXT_PRIMARY};
            }}
            QTextEdit:focus, QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
                border: 1px solid {ACCENT_BLUE};
            }}
            QComboBox::drop-down {{
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 25px;
                border-left-width: 1px;
                border-left-color: {BORDER_COLOR};
                border-left-style: solid;
                border-top-right-radius: 8px;
                border-bottom-right-radius: 8px;
            }}
            QStatusBar {{
                font-size: 10pt;
                color: {TEXT_SECONDARY};
            }}
            #versionLabel {{
                color: {TEXT_SECONDARY};
                font-size: 9pt;
                padding-top: 0px;
            }}
        """)

    # --- Metody uproszczone ---
    def populate_algorithms(self):
        for alg in self.algorithm_manager.get_all_algorithms():
            self.algorithm_combo.addItem(alg.name)
    
    def populate_file_algorithms(self):
        for alg in self.algorithm_manager.get_all_algorithms():
            self.file_algorithm_combo.addItem(alg.name)
    
    def on_algorithm_changed(self, name):
        self.current_algorithm = self.algorithm_manager.get_algorithm(name)
        if not self.current_algorithm:
            return

        # najpierw sprawdź, czy algorytm akceptuje klucz liczbowy (spin)
        prefers_numeric = False
        try:
            if self.current_algorithm.validate_key(self.key_spin.value()):
                prefers_numeric = True
        except Exception:
            prefers_numeric = False

        # jeśli nie, spróbuj sprawdzić klucz tekstowy (najpierw aktualne pole, potem przykładowy string)
        if not prefers_numeric:
            try:
                if self.current_algorithm.validate_key(self.key_text.text()):
                    prefers_numeric = False
                elif self.current_algorithm.validate_key("K"):  # próbka tekstowa
                    prefers_numeric = False
                else:
                    # nie rozpoznano jako tekstowy — domyślnie pozostaw numeric (bez zmiany)
                    prefers_numeric = False
            except Exception:
                # w razie błędu w validate_key nie zmieniamy preferencji wcześniej wykrytej
                pass

        # ustawiamy widoczność dla obu widoków (tekst i plik)
        if hasattr(self, 'key_stack'):
            self.key_stack.setCurrentIndex(0 if prefers_numeric else 1)
        if hasattr(self, 'file_key_stack'):
            self.file_key_stack.setCurrentIndex(0 if prefers_numeric else 1)

        # Pokaż/ukryj wybór rozmiaru klucza AES
        is_aes = "AES" in name
        if hasattr(self, 'aes_key_size_label'):
            self.aes_key_size_label.setVisible(is_aes)
            self.aes_key_size_combo.setVisible(is_aes)
        if hasattr(self, 'file_aes_key_size_label'):
            self.file_aes_key_size_label.setVisible(is_aes)
            self.file_aes_key_size_combo.setVisible(is_aes)

        is_rsa = "RSA" in name
        if hasattr(self, 'rsa_group_box'):
            self.rsa_group_box.setVisible(is_rsa)
        
        # Ukryj standardowe pole klucza dla RSA
        if hasattr(self, 'key_stack'):
            self.key_stack.setVisible(not is_rsa)
        if hasattr(self, 'file_key_stack'):
            self.file_key_stack.setVisible(not is_rsa)

        self.statusBar().showMessage(f"Aktywny: {name}")
    
    def generate_rsa_keys(self):
        """Generuje i wyświetla nową parę kluczy RSA."""
        try:
            rsa_alg = self.algorithm_manager.get_algorithm("RSA")
            public_key, private_key = rsa_alg.generate_keys()
            
            self.public_key_text.setPlainText(str(public_key))
            self.private_key_text.setPlainText(str(private_key))
            self.statusBar().showMessage("Wygenerowano nowe klucze RSA")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Generowanie kluczy RSA: {str(e)}")
    
    def encrypt_text(self):
        if not self._validate_text_input(): return
        try:
            self.logger.clear()
            plaintext = self.input_text.toPlainText()
            algorithm_name = self.current_algorithm.name
            
            self.logger.set_algorithm(algorithm_name, self.rsa_mode_combo.currentText() if "RSA" in algorithm_name else None)
            self.logger.info(f"Rozpoczęcie szyfrowania", f"Algorytm: {algorithm_name}", is_step=True)
            self.logger.log_input_preview(plaintext)
            
            if "RSA" in algorithm_name:
                mode = self.rsa_mode_combo.currentText()
                if mode == "Szyfruj / Deszyfruj":
                    self.logger.info("Tryb operacji", "Szyfruj / Deszyfruj")
                    
                    public_key_str = self.public_key_text.toPlainText()
                    if not public_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz publiczny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(public_key_str)
                        e, n = key
                        key_bits = len(bin(n)) - 2
                        self.logger.success("Klucz publiczny", f"e={e}, n={str(n)[:50]}...", is_step=True)
                        self.logger.debug("Rozmiar modułu (bity)", str(key_bits))
                        self.logger.explain_algorithm("RSA", key_bits)
                        # Szczegółowe logowanie RSA
                        self.logger.log_rsa_details(key_bits, is_encrypt=True)
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    
                    self.logger.info("Przygotowanie tekstu", f"Rozmiar oryginalny: {len(plaintext)} znaków", is_step=True)
                    self.logger.debug("Kodowanie tekstu", "UTF-8")
                    
                    self.logger.info("Szyfrowanie tekstu", f"Kryptografia RSA z kluczem {len(bin(n))-2}-bitowym", is_step=True)
                    encrypted = self.current_algorithm.encrypt(plaintext, key)
                    self.logger.success("Szyfrowanie", f"Ukończone, rozmiar: {len(encrypted)} bajtów")
                    
                    compression_ratio = (len(encrypted) / len(plaintext.encode('utf-8'))) * 100 if plaintext else 0
                    self.logger.debug("Stosunek rozmiaru", f"{compression_ratio:.1f}% rozmiaru oryginalnego")
                    
                    encrypted_hex = encrypted.hex()
                    self.output_text.setPlainText(encrypted_hex)
                    self.logger.info("Konwersja wyniku", "Tekst → Heksadecymalny (BASE16)", is_step=True)
                    self.logger.debug("Rozmiar heksadecymalny", f"{len(encrypted_hex)} znaków")
                    self.logger.set_result(encrypted_hex)
                    self.statusBar().showMessage("Zaszyfrowano!")
                    
                elif mode == "Podpisz / Weryfikuj":
                    self.logger.info("Tryb operacji", "Podpisz / Weryfikuj")
                    
                    private_key_str = self.private_key_text.toPlainText()
                    if not private_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz prywatny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(private_key_str)
                        d, n = key
                        key_bits = len(bin(n)) - 2
                        self.logger.success("Klucz prywatny", f"Załadowany, n={str(n)[:50]}...", is_step=True)
                        self.logger.debug("Rozmiar modułu (bity)", str(key_bits))
                        self.logger.explain_algorithm("RSA", key_bits)
                        # Szczegółowe logowanie RSA
                        self.logger.log_rsa_details(key_bits, is_encrypt=False)
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    
                    self.logger.info("Przygotowanie tekstu", f"Rozmiar: {len(plaintext)} znaków", is_step=True)
                    self.logger.debug("Kodowanie tekstu", "UTF-8")
                    
                    self.logger.info("Podpisywanie tekstu", f"Algorytm: RSA z {len(bin(n))-2}-bitowym kluczem", is_step=True)
                    signed = self.current_algorithm.sign(plaintext.encode('utf-8'), key)
                    self.logger.success("Podpis", f"Utworzony, rozmiar: {len(signed)} bajtów")
                    
                    self.logger.debug("Typ podpisu", "RSA PSS (PKCS#1 v2.1)")
                    
                    signed_hex = signed.hex()
                    self.output_text.setPlainText(signed_hex)
                    self.logger.info("Konwersja wyniku", "Podpis binarny → Heksadecymalny (BASE16)", is_step=True)
                    self.logger.debug("Rozmiar heksadecymalny", f"{len(signed_hex)} znaków")
                    self.logger.set_result(signed_hex)
                    self.statusBar().showMessage("Podpisano!")
            else:
                key = self._get_text_key()
                options = {}
                if "AES" in algorithm_name:
                    key_size_str = self.aes_key_size_combo.currentText().split(' ')[0].replace('AES-', '')
                    key_size = int(key_size_str) // 8
                    options['key_size'] = key_size
                    self.logger.info("Parametry AES", f"Rozmiar klucza: {key_size_str} bitów ({key_size} bajtów)", is_step=True)
                    self.logger.explain_algorithm(algorithm_name, key_size)
                    self.logger.debug("Tryb operacji", "ECB (Electronic Codebook)")
                    # Szczegółowe logowanie AES
                    self.logger.log_aes_details(len(plaintext), key_size, is_encrypt=True)
                elif "Cezara" in algorithm_name:
                    self.logger.info("Klucz szyfrowania", f"Przesunięcie: {key} pozycji", is_step=True)
                    self.logger.explain_algorithm(algorithm_name, key)
                    # Szczegółowe logowanie Cezara
                    self.logger.log_caesar_details(plaintext, key, is_encrypt=True)
                elif "Vigenere" in algorithm_name:
                    self.logger.info("Klucz szyfrowania", f"Klucz: '{key}' (długość: {len(str(key))})", is_step=True)
                    self.logger.explain_algorithm(algorithm_name, key)
                    # Szczegółowe logowanie Vigenere'a
                    self.logger.log_vigenere_details(plaintext, str(key), is_encrypt=True)
                elif "Beaufort" in algorithm_name:
                    self.logger.info("Klucz szyfrowania", f"Klucz: '{key}' (długość: {len(str(key))})", is_step=True)
                    self.logger.explain_algorithm(algorithm_name, key)
                    # Szczegółowe logowanie Beauforta
                    self.logger.log_beaufort_details(plaintext, str(key), is_encrypt=True)
                elif "ChaCha" in algorithm_name:
                    self.logger.info("Klucz szyfrowania", f"Długość: {len(str(key))} znaków", is_step=True)
                    self.logger.explain_algorithm(algorithm_name, key)
                    # Szczegółowe logowanie ChaCha20
                    self.logger.log_chacha20_details(len(plaintext), key_size=32, is_encrypt=True)
                else:
                    self.logger.info("Klucz szyfrowania", f"Długość: {len(str(key))} znaków", is_step=True)
                    self.logger.explain_algorithm(algorithm_name, key)
                
                self.logger.info("Przygotowanie tekstu", f"Rozmiar oryginalny: {len(plaintext)} znaków", is_step=True)
                self.logger.info("Szyfrowanie tekstu", f"Algorytm: {algorithm_name}", is_step=True)
                encrypted = self.current_algorithm.encrypt(plaintext, key, **options)
                self.logger.success("Szyfrowanie", f"Ukończone, rozmiar wyjścia: {len(encrypted)} znaków")
                
                compression_ratio = (len(encrypted) / len(plaintext)) * 100 if plaintext else 0
                self.logger.debug("Stosunek rozmiaru", f"{compression_ratio:.1f}% rozmiaru oryginalnego")
                
                self.output_text.setPlainText(encrypted)
                self.logger.debug("Format wyjścia", "Tekst szyfrowany")
                self.logger.set_result(encrypted)
                self.statusBar().showMessage("Zaszyfrowano.")
            
            self.logger.success("KONIEC", "Operacja szyfrowania zakończona pomyślnie!")
            self.refresh_logs_view()
            
        except Exception as e:
            self.logger.set_error()
            self.logger.error("Błąd szyfrowania", str(e))
            self.refresh_logs_view()
            QMessageBox.critical(self, "Błąd", f"Szyfrowanie: {str(e)}")
    
    def decrypt_text(self):
        if not self._validate_text_input(): return
        try:
            self.logger.clear()
            algorithm_name = self.current_algorithm.name
            
            self.logger.set_algorithm(algorithm_name, self.rsa_mode_combo.currentText() if "RSA" in algorithm_name else None)
            self.logger.info("Rozpoczęcie deszyfrowania", f"Algorytm: {algorithm_name}")
            
            if "RSA" in algorithm_name:
                mode = self.rsa_mode_combo.currentText()
                if mode == "Szyfruj / Deszyfruj":
                    self.logger.info("Tryb operacji", "Szyfruj / Deszyfruj")
                    
                    private_key_str = self.private_key_text.toPlainText()
                    if not private_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz prywatny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(private_key_str)
                        d, n = key
                        key_bits = len(bin(n)) - 2
                        self.logger.success("Klucz prywatny", f"Załadowany, n={str(n)[:50]}...")
                        self.logger.debug("Rozmiar modułu (bity)", str(key_bits))
                        # Szczegółowe logowanie RSA
                        self.logger.log_rsa_details(key_bits, is_encrypt=False)
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    
                    try:
                        self.logger.log_input_preview(self.input_text.toPlainText(), label="Tekst szyfrowany")
                        self.logger.debug("Etap", "Konwersja heksadecymalny → binarny (bytes)")
                        encrypted_data = bytes.fromhex(self.input_text.toPlainText())
                        self.logger.success("Parsowanie", f"Rozmiar binarny: {len(encrypted_data)} bajtów")
                    except Exception as e:
                        self.logger.error("Błąd parsowania", str(e))
                        raise
                    
                    self.logger.info("Deszyfrowanie", f"RSA {len(bin(n))-2}-bitowe")
                    decrypted = self.current_algorithm.decrypt(encrypted_data, key)
                    self.logger.success("Deszyfrowanie", f"Ukończone, rozmiar: {len(decrypted)} bajtów")
                    
                    self.input_text.clear()
                    decrypted_text = decrypted.decode('utf-8', errors='replace')
                    self.output_text.setPlainText(decrypted_text)
                    self.logger.info("Konwersja wyniku", "Bytes → UTF-8 tekst")
                    self.logger.debug("Tekst wyjściowy", f"Rozmiar: {len(decrypted_text)} znaków")
                    self.logger.set_result(decrypted_text)
                    self.statusBar().showMessage("Deszyfrowano!")
                    
                elif mode == "Podpisz / Weryfikuj":
                    self.logger.info("Tryb operacji", "Podpisz / Weryfikuj")
                    
                    public_key_str = self.public_key_text.toPlainText()
                    if not public_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz publiczny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(public_key_str)
                        e, n = key
                        key_bits = len(bin(n)) - 2
                        self.logger.success("Klucz publiczny", f"Załadowany, e={e}")
                        self.logger.debug("Rozmiar modułu (bity)", str(key_bits))
                        # Szczegółowe logowanie RSA
                        self.logger.log_rsa_details(key_bits, is_encrypt=True)
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    
                    # KROK DIAGNOSTYCZNY: Spróbuj automatycznie wyciągnąć klucz publiczny z prywatnego
                    first_num, n = key
                    if first_num > 65537 and first_num < n:
                        self.logger.warning("Detektora klucza", "Wykryto klucz prywatny zamiast publicznego")
                        try:
                            key = self._extract_public_from_private_key(key)
                            self.logger.success("Wyodrębnienie", "Klucz publiczny wyodrębniony z prywatnego")
                            QMessageBox.information(self, "Info", 
                                "Wykryto klucz prywatny w polu klucza publicznego.\n"
                                "Automatycznie wyodrębniony klucz publiczny (e=65537, n).\n"
                                "Kontynuuję weryfikację...")
                        except Exception:
                            pass
                    
                    try:
                        self.logger.info("Parsowanie podpisu", f"Rozmiar: {len(self.input_text.toPlainText())} znaków")
                        self.logger.debug("Etap", "Konwersja heksadecymalny → binarny (bytes)")
                        signed_data = bytes.fromhex(self.input_text.toPlainText().strip())
                        self.logger.success("Parsowanie podpisu", f"Rozmiar binarny: {len(signed_data)} bajtów")
                    except Exception:
                        self.logger.error("Błąd parsowania podpisu", "Nieprawidłowy format (oczekiwany hex)")
                        QMessageBox.warning(self, "Błąd", "Nieprawidłowy format podpisu (oczekiwany hex).")
                        return

                    # Przygotuj listę kandydatów danych do weryfikacji
                    candidates = []
                    out_text = self.output_text.toPlainText()
                    if out_text:
                        candidates.append(("output_utf8", out_text.encode('utf-8')))
                    if out_text:
                        try:
                            candidates.append(("output_hex", bytes.fromhex(out_text.strip())))
                        except Exception:
                            pass

                    self.logger.info("Weryfikacja podpisu", f"Próbuję {len(candidates)} reprezentacji danych")
                    tried_methods = []
                    verified = False
                    which = None
                    for name, candidate in candidates:
                        try:
                            self.logger.debug("Próba weryfikacji", f"Metoda: {name}")
                            if self.current_algorithm.verify(candidate, signed_data, key):
                                verified = True
                                which = name
                                self.logger.success("Weryfikacja", f"✓ Podpis PRAWIDŁOWY!")
                                self.logger.debug("Metoda", f"Dane w formacie: {which}")
                                break
                        except Exception:
                            tried_methods.append(name)

                    if verified:
                        self.logger.success("KONIEC", "Weryfikacja podpisu zakończona pomyślnie!")
                        self.logger.set_result(f"Podpis PRAWIDŁOWY - Metoda: {which}")
                        self.refresh_logs_view()
                        QMessageBox.information(self, "Sukces", f"✓ Podpis jest prawidłowy! (metoda: {which})")
                        self.statusBar().showMessage("Podpis zweryfikowany!")
                    else:
                        self.logger.error("Weryfikacja", "✗ Podpis NIEPRAWIDŁOWY - nie pasuje!")
                        self.logger.warning("KONIEC", "Weryfikacja nieudana!")
                        self.logger.set_error()
                        self.refresh_logs_view()
                        QMessageBox.warning(self, "Błąd", "✗ Podpis jest NIEPRAWIDŁOWY!\n\n"
                                            "Wskazówka: Upewnij się, że:\n"
                                            "- Używasz klucza publicznego osoby, która podpisała dane\n"
                                            "- Dane nie zostały zmienione od czasu podpisania\n"
                                            "- Podpis jest w formacie hex (wklejony do pola Input)")
                        self.statusBar().showMessage("Błąd: Podpis NIEPRAWIDŁOWY!")
            else:
                key = self._get_text_key()
                options = {}
                ciphertext_input = self.input_text.toPlainText()
                
                if "AES" in algorithm_name:
                    key_size_str = self.aes_key_size_combo.currentText().split(' ')[0].replace('AES-', '')
                    key_size = int(key_size_str) // 8
                    options['key_size'] = key_size
                    self.logger.info("Parametry AES", f"Rozmiar klucza: {key_size_str} bitów ({key_size} bajtów)")
                    self.logger.debug("Tryb operacji", "ECB (Electronic Codebook)")
                    # Szczegółowe logowanie AES
                    self.logger.log_aes_details(len(ciphertext_input), key_size, is_encrypt=False)
                elif "Cezara" in algorithm_name:
                    self.logger.info("Klucz deszyfrowania", f"Przesunięcie: {key} pozycji")
                    # Szczegółowe logowanie Cezara
                    self.logger.log_caesar_details(ciphertext_input, key, is_encrypt=False)
                elif "Vigenere" in algorithm_name:
                    self.logger.info("Klucz deszyfrowania", f"Klucz: '{key}' (długość: {len(str(key))})")
                    # Szczegółowe logowanie Vigenere'a
                    self.logger.log_vigenere_details(ciphertext_input, str(key), is_encrypt=False)
                elif "Beaufort" in algorithm_name:
                    self.logger.info("Klucz deszyfrowania", f"Klucz: '{key}' (długość: {len(str(key))})")
                    # Szczegółowe logowanie Beauforta
                    self.logger.log_beaufort_details(ciphertext_input, str(key), is_encrypt=False)
                elif "ChaCha" in algorithm_name:
                    self.logger.info("Klucz deszyfrowania", f"Długość: {len(str(key))} znaków")
                    # Szczegółowe logowanie ChaCha20
                    self.logger.log_chacha20_details(len(ciphertext_input), key_size=32, is_encrypt=False)
                else:
                    self.logger.info("Klucz deszyfrowania", f"Długość: {len(str(key))} znaków")
                
                self.logger.log_input_preview(ciphertext_input, label="Tekst szyfrowany")
                self.logger.info("Deszyfrowanie tekstu", f"Algorytm: {algorithm_name}", is_step=True)
                decrypted = self.current_algorithm.decrypt(ciphertext_input, key, **options)
                self.logger.success("Deszyfrowanie", f"Ukończone, rozmiar wyniku: {len(decrypted)} znaków")
                
                compression_ratio = (len(decrypted) / len(ciphertext_input)) * 100 if ciphertext_input else 0
                self.logger.debug("Stosunek rozmiaru", f"{compression_ratio:.1f}% rozmiaru szyfrowanego")
                
                self.input_text.clear()
                self.output_text.setPlainText(decrypted)
                self.logger.debug("Format wyjścia", "Tekst odszyfrowany")
                self.logger.set_result(decrypted)
                self.statusBar().showMessage("Deszyfrowano!")
            
            self.logger.success("KONIEC", "Operacja deszyfrowania zakończona pomyślnie!")
            self.refresh_logs_view()
            
        except Exception as e:
            self.logger.set_error()
            self.logger.error("Błąd deszyfrowania", str(e))
            self.refresh_logs_view()
            QMessageBox.critical(self, "Błąd", f"Deszyfrowanie: {str(e)}")
    
    def clear_text(self):
        self.input_text.clear()
        self.output_text.clear()
        self.statusBar().showMessage("Wyczyszczono")
    
    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Wybierz plik", "", "Wszystkie pliki (*)")
        if path:
            self.file_path_input.setText(path)
            self.statusBar().showMessage(f"Wybrano: {os.path.basename(path)}")
    
    def encrypt_file(self):
        if not self._validate_file_input(): return
        try:
            self.logger.clear()
            file_path = self.file_path_input.text()
            file_name = os.path.basename(file_path)
            alg = self.algorithm_manager.get_algorithm(self.file_algorithm_combo.currentText())
            
            mode = self.rsa_mode_combo.currentText() if "RSA" in alg.name else None
            self.logger.set_algorithm(alg.name, mode)
            
            self.logger.info("Szyfrowanie pliku", f"Plik: {file_name}")
            self.logger.debug("Ścieżka", file_path)
            self.logger.info("Algorytm", alg.name)
            
            if "RSA" in alg.name:
                mode = self.rsa_mode_combo.currentText()
                if mode == "Szyfruj / Deszyfruj":
                    self.logger.info("Tryb", "RSA Szyfruj / Deszyfruj")
                    
                    public_key_str = self.public_key_text.toPlainText()
                    if not public_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz publiczny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(public_key_str)
                        e, n = key
                        self.logger.success("Klucz publiczny", f"e={e}, n={str(n)[:40]}...")
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    
                    self.logger.info("Wczytywanie pliku", "Trwa...")
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    self.logger.log_input_preview(content, label="Plik wejściowy")
                    
                    self.logger.info("Szyfrowanie", "Trwa...")
                    encrypted = alg.encrypt(content, key)
                    self.logger.success("Szyfrowanie", f"Ukończone, rozmiar: {len(encrypted)} bajtów")
                    
                    output_path = file_path + ".enc"
                    self.logger.info("Zapis pliku", f"Do: {os.path.basename(output_path)}")
                    with open(output_path, 'wb') as f:
                        f.write(encrypted)
                    self.logger.success("Zapis", "Plik zapisany")
                    self.logger.set_result(f"Plik: {os.path.basename(output_path)} ({len(encrypted)} bajtów)")
                    
                    QMessageBox.information(self, "Sukces", "Plik zaszyfrowany do .enc")
                    self.statusBar().showMessage("Plik zaszyfrowany!")
                    
                elif mode == "Podpisz / Weryfikuj":
                    self.logger.info("Tryb", "RSA Podpisz / Weryfikuj")
                    
                    private_key_str = self.private_key_text.toPlainText()
                    if not private_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz prywatny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(private_key_str)
                        d, n = key
                        self.logger.success("Klucz prywatny", f"Załadowany, n={str(n)[:40]}...")
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    
                    self.logger.info("Wczytywanie pliku", "Trwa...")
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    self.logger.log_input_preview(content, label="Plik wejściowy")
                    
                    self.logger.info("Podpisywanie", "Trwa...")
                    signed = alg.sign(content, key)
                    self.logger.success("Podpis", f"Utworzony, rozmiar: {len(signed)} bajtów")
                    
                    output_path = file_path + ".sig"
                    self.logger.info("Zapis podpisu", f"Do: {os.path.basename(output_path)}")
                    with open(output_path, 'wb') as f:
                        f.write(signed)
                    self.logger.success("Zapis", "Podpis zapisany")
                    self.logger.set_result(f"Podpis: {os.path.basename(output_path)} ({len(signed)} bajtów)")
                    
                    QMessageBox.information(self, "Sukces", "Plik podpisany do .sig")
                    self.statusBar().showMessage("Plik podpisany!")
            else:
                self.logger.info("Wczytywanie pliku", "Trwa...")
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.logger.log_input_preview(content, label="Plik wejściowy")
                
                key = self._get_file_key()
                options = {}
                if "AES" in alg.name:
                    key_size_str = self.file_aes_key_size_combo.currentText().split(' ')[0].replace('AES-', '')
                    key_size = int(key_size_str)
                    options['key_size'] = key_size // 8
                    self.logger.info("Parametry AES", f"Rozmiar klucza: {key_size} bitów")
                    # Szczegółowe logowanie AES
                    self.logger.log_aes_details(len(content), key_size // 8, is_encrypt=True)
                elif "Cezara" in alg.name:
                    self.logger.info("Klucz", f"Przesunięcie: {key} pozycji")
                    self.logger.log_caesar_details(content, key, is_encrypt=True)
                elif "Vigenere" in alg.name:
                    self.logger.info("Klucz", f"Klucz: '{key}'")
                    self.logger.log_vigenere_details(content, str(key), is_encrypt=True)
                elif "Beaufort" in alg.name:
                    self.logger.info("Klucz", f"Klucz: '{key}'")
                    self.logger.log_beaufort_details(content, str(key), is_encrypt=True)
                elif "ChaCha" in alg.name:
                    self.logger.info("Klucz", f"Długość: {len(str(key))} znaków")
                    self.logger.log_chacha20_details(len(content), key_size=32, is_encrypt=True)
                
                self.logger.info("Szyfrowanie", "Trwa...", is_step=True)
                encrypted = alg.encrypt(content, key, **options)
                self.logger.success("Szyfrowanie", f"Ukończone, rozmiar wyjścia: {len(encrypted)} znaków")
                
                self.logger.info("Zapis pliku", "Trwa...")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(encrypted)
                self.logger.success("Zapis", "Plik zaszyfrowany")
                self.logger.set_result(f"Plik zaszyfrowany ({len(encrypted)} znaków)")
                
                QMessageBox.information(self, "Sukces", "Plik zaszyfrowany.")
                self.statusBar().showMessage("Plik zaszyfrowany!")
            
            self.logger.success("KONIEC", "Operacja szyfrowania pliku zakończona pomyślnie!")
            self.refresh_logs_view()
            
        except Exception as e:
            self.logger.set_error()
            self.logger.error("Błąd szyfrowania pliku", str(e))
            self.refresh_logs_view()
            QMessageBox.critical(self, "Błąd", f"Szyfrowanie pliku: {str(e)}")
    
    def decrypt_file(self):
        if not self._validate_file_input(): return
        try:
            self.logger.clear()
            file_path = self.file_path_input.text()
            file_name = os.path.basename(file_path)
            alg = self.algorithm_manager.get_algorithm(self.file_algorithm_combo.currentText())
            
            mode = self.rsa_mode_combo.currentText() if "RSA" in alg.name else None
            self.logger.set_algorithm(alg.name, mode)
            
            self.logger.info("Deszyfrowanie pliku", f"Plik: {file_name}")
            self.logger.debug("Ścieżka", file_path)
            self.logger.info("Algorytm", alg.name)
            if "RSA" in alg.name:
                mode = self.rsa_mode_combo.currentText()
                if mode == "Szyfruj / Deszyfruj":
                    self.logger.info("Tryb", "RSA Szyfruj / Deszyfruj")
                    
                    private_key_str = self.private_key_text.toPlainText()
                    if not private_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz prywatny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(private_key_str)
                        d, n = key
                        self.logger.success("Klucz prywatny", f"Załadowany, n={str(n)[:40]}...")
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    
                    self.logger.info("Wczytywanie zaszyfrowanego pliku", "Trwa...")
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    self.logger.log_input_preview(content, label="Plik zaszyfrowany")
                    
                    self.logger.info("Deszyfrowanie", "Trwa...")
                    decrypted = alg.decrypt(content, key)
                    self.logger.success("Deszyfrowanie", f"Ukończone, rozmiar: {len(decrypted)} bajtów")
                    
                    output_path = file_path.replace(".enc", "")
                    if output_path == file_path:
                        output_path = file_path + ".dec"
                    
                    self.logger.info("Zapis odszyfrowanego pliku", f"Do: {os.path.basename(output_path)}")
                    with open(output_path, 'wb') as f:
                        f.write(decrypted)
                    self.logger.success("Zapis", "Plik deszyfrowany")
                    self.logger.set_result(f"Plik: {os.path.basename(output_path)} ({len(decrypted)} bajtów)")
                    
                    QMessageBox.information(self, "Sukces", f"Plik deszyfrowany do {os.path.basename(output_path)}!")
                    self.statusBar().showMessage("Plik deszyfrowany!")
                elif mode == "Podpisz / Weryfikuj":
                    self.logger.info("Tryb", "RSA Podpisz / Weryfikuj")
                    
                    public_key_str = self.public_key_text.toPlainText()
                    if not public_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz publiczny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(public_key_str)
                        self.logger.success("Klucz publiczny", "Załadowany")
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    
                    # KROK DIAGNOSTICZNY: Spróbuj automatycznie wyciągnąć klucz publiczny z prywatnego
                    # Jeśli pierwsza liczba > 65537, to prawdopodobnie (d, n) zamiast (e, n)
                    first_num, n = key
                    if first_num > 65537 and first_num < n:
                        # Wygląda na klucz prywatny (d > e)
                        # Wyciągnij publiczny klucz
                        try:
                            key = self._extract_public_from_private_key(key)
                            self.logger.success("Wyodrębnienie", "Klucz publiczny wyodrębniony z prywatnego")
                            QMessageBox.information(self, "Info", 
                                "Wykryto klucz prywatny w polu klucza publicznego.\n"
                                "Automatycznie wyodrębniony klucz publiczny (e=65537, n).\n"
                                "Kontynuuję weryfikację...")
                        except Exception:
                            self.logger.error("Wyodrębnienie", "Nie mogę wyciągnąć klucza publicznego!")
                            QMessageBox.warning(self, "Błąd", "Nie mogę wyciągnąć klucza publicznego z prywatnego!")
                            return
                    
                    # Czytaj plik podpisu
                    self.logger.info("Wczytywanie podpisu", "Trwa...")
                    sig_path = self.file_path_input.text()
                    with open(sig_path, 'rb') as f:
                        signature = f.read()
                    self.logger.success("Wczytywanie podpisu", f"Rozmiar: {len(signature)} bajtów")
                    
                    # Czytaj oryginalny plik danych (bez .sig)
                    data_path = sig_path.replace(".sig", "")
                    if data_path == sig_path:
                        self.logger.error("Format pliku", "Plik powinien mieć rozszerzenie .sig!")
                        QMessageBox.warning(self, "Błąd", "Plik powinien mieć rozszerzenie .sig!")
                        return
                    
                    self.logger.info("Wczytywanie danych", f"Z: {os.path.basename(data_path)}")
                    with open(data_path, 'rb') as f:
                        data = f.read()
                    self.logger.success("Wczytywanie danych", f"Rozmiar: {len(data)} bajtów")
                    
                    # Weryfikuj podpis
                    self.logger.info("Weryfikacja podpisu", "Trwa...")
                    is_valid = alg.verify(data, signature, key)
                    if is_valid:
                        self.logger.success("Weryfikacja", "✓ PRAWIDŁOWY")
                        self.logger.success("KONIEC", "Weryfikacja podpisu zakończona pomyślnie!")
                        self.logger.set_result(f"Podpis PRAWIDŁOWY - Plik: {os.path.basename(data_path)}")
                        self.refresh_logs_view()
                        QMessageBox.information(self, "Sukces", f"✓ Podpis pliku {os.path.basename(data_path)} jest PRAWIDŁOWY!")
                        self.statusBar().showMessage("Podpis zweryfikowany!")
                    else:
                        self.logger.error("Weryfikacja", "✗ NIEPRAWIDŁOWY")
                        self.logger.warning("KONIEC", "Podpis nie pasuje do danych!")
                        self.logger.set_error()
                        self.refresh_logs_view()
                        QMessageBox.critical(self, "Błąd", f"✗ Podpis pliku {os.path.basename(data_path)} jest NIEPRAWIDŁOWY!\n\n"
                                            "Wskazówka: Upewnij się, że:\n"
                                            "- Używasz klucza publicznego osoby, która podpisała plik\n"
                                            "- Plik nie został zmieniony od czasu podpisania")
                        self.statusBar().showMessage("Błąd: Podpis NIEPRAWIDŁOWY!")
            else:
                self.logger.info("Wczytywanie zaszyfrowanego pliku", f"Plik: {os.path.basename(self.file_path_input.text())}")
                with open(self.file_path_input.text(), 'r', encoding='utf-8') as f:
                    content = f.read()
                self.logger.log_input_preview(content, label="Plik zaszyfrowany")
                
                key = self._get_file_key()
                options = {}
                if "AES" in alg.name:
                    key_size_str = self.file_aes_key_size_combo.currentText().split(' ')[0].replace('AES-', '')
                    key_size = int(key_size_str) // 8
                    options['key_size'] = key_size
                    self.logger.info("Parametry AES", f"Rozmiar klucza: {key_size_str} bitów")
                    # Szczegółowe logowanie AES
                    self.logger.log_aes_details(len(content), key_size, is_encrypt=False)
                elif "Cezara" in alg.name:
                    self.logger.info("Klucz", f"Przesunięcie: {key} pozycji")
                    self.logger.log_caesar_details(content, key, is_encrypt=False)
                elif "Vigenere" in alg.name:
                    self.logger.info("Klucz", f"Klucz: '{key}'")
                    self.logger.log_vigenere_details(content, str(key), is_encrypt=False)
                elif "Beaufort" in alg.name:
                    self.logger.info("Klucz", f"Klucz: '{key}'")
                    self.logger.log_beaufort_details(content, str(key), is_encrypt=False)
                elif "ChaCha" in alg.name:
                    self.logger.info("Klucz", f"Długość: {len(str(key))} znaków")
                    self.logger.log_chacha20_details(len(content), key_size=32, is_encrypt=False)
                
                self.logger.info("Deszyfrowanie", "Trwa...", is_step=True)
                decrypted = alg.decrypt(content, key, **options)
                self.logger.success("Deszyfrowanie", f"Ukończone, rozmiar: {len(decrypted)} znaków")
                
                self.logger.info("Zapis odszyfrowanego pliku", f"Do: {os.path.basename(self.file_path_input.text())}")
                with open(self.file_path_input.text(), 'w', encoding='utf-8') as f:
                    f.write(decrypted)
                self.logger.success("Zapis", "Plik odszyfrowany")
                self.logger.set_result(f"Plik odszyfrowany ({len(decrypted)} znaków)")
                self.logger.success("KONIEC", "Deszyfrowanie pliku zakończone pomyślnie!")
                self.refresh_logs_view()
                
                QMessageBox.information(self, "Sukces", "Plik deszyfrowany!")
                self.statusBar().showMessage("Plik deszyfrowany!")
        except Exception as e:
            self.logger.set_error()
            self.logger.error("KONIEC", f"Błąd! {str(e)}")
            self.refresh_logs_view()
            QMessageBox.critical(self, "Błąd", f"Deszyfrowanie pliku: {str(e)}")
    
    def _validate_text_input(self):
        if not self.current_algorithm:
            QMessageBox.warning(self, "Błąd", "Wybierz algorytm!")
            return False
        if not self.input_text.toPlainText():
            QMessageBox.warning(self, "Błąd", "Wprowadź tekst!")
            return False
        
        if "RSA" in self.current_algorithm.name:
            mode = self.rsa_mode_combo.currentText()
            if mode == "Szyfruj / Deszyfruj":
                if not self.public_key_text.toPlainText() and not self.private_key_text.toPlainText():
                    QMessageBox.warning(self, "Błąd", "Wprowadź klucz publiczny lub prywatny dla RSA!")
                    return False
            elif mode == "Podpisz / Weryfikuj":
                if not self.public_key_text.toPlainText() and not self.private_key_text.toPlainText():
                    QMessageBox.warning(self, "Błąd", "Wprowadź klucz publiczny lub prywatny dla RSA!")
                    return False
        else:
            key = self._get_text_key()
            try:
                if not self.current_algorithm.validate_key(key):
                    QMessageBox.warning(self, "Błąd", "Nieprawidłowy klucz!")
                    return False
            except Exception:
                QMessageBox.warning(self, "Błąd", "Nieprawidłowy klucz!")
                return False
        return True
    
    def _validate_file_input(self):
        alg = self.algorithm_manager.get_algorithm(self.file_algorithm_combo.currentText())
        if not alg:
            QMessageBox.warning(self, "Błąd", "Wybierz algorytm!")
            return False
        if not self.file_path_input.text():
            QMessageBox.warning(self, "Błąd", "Wybierz plik!")
            return False
        
        if "RSA" in alg.name:
            mode = self.rsa_mode_combo.currentText()
            if mode == "Szyfruj / Deszyfruj":
                if not self.public_key_text.toPlainText() and not self.private_key_text.toPlainText():
                    QMessageBox.warning(self, "Błąd", "Wprowadź klucz publiczny lub prywatny dla RSA!")
                    return False
            elif mode == "Podpisz / Weryfikuj":
                if not self.public_key_text.toPlainText() and not self.private_key_text.toPlainText():
                    QMessageBox.warning(self, "Błąd", "Wprowadź klucz publiczny lub prywatny dla RSA!")
                    return False
        else:
            key = self._get_file_key()
            try:
                if not alg.validate_key(key):
                    QMessageBox.warning(self, "Błąd", "Nieprawidłowy klucz!")
                    return False
            except Exception:
                QMessageBox.warning(self, "Błąd", "Nieprawidłowy klucz!")
                return False
        return True

    # pomocnicze metody do pobierania aktualnego klucza
    def _get_text_key(self):
        if hasattr(self, 'key_stack') and self.key_stack.currentIndex() == 0:
            return self.key_spin.value()
        return self.key_text.text()

    def _get_file_key(self):
        if hasattr(self, 'file_key_stack') and self.file_key_stack.currentIndex() == 0:
            return self.file_key_spin.value()
        return self.file_key_text.text()

    def _parse_rsa_key_safe(self, key_str: str) -> tuple:
        """
        Bezpiecznie parsuje string klucza RSA na krotkę (e, n) lub (d, n).
        
        Zwraca: tuple (e/d, n) lub raises ValueError/SyntaxError
        """
        if not key_str or not key_str.strip():
            raise ValueError("Klucz nie może być pusty")
        
        try:
            # Użyj ast.literal_eval zamiast eval() dla bezpieczeństwa
            parsed = ast.literal_eval(key_str.strip())
            
            if not isinstance(parsed, tuple) or len(parsed) != 2:
                raise ValueError("Klucz RSA musi być krotką (liczba, liczba)")
            
            if not (isinstance(parsed[0], int) and isinstance(parsed[1], int)):
                raise ValueError("Obie części klucza muszą być liczbami całkowitymi")
            
            return parsed
        except (ValueError, SyntaxError) as e:
            raise ValueError(f"Nieprawidłowy format klucza RSA: {str(e)}")
    
    def _extract_public_from_private_key(self, private_key: tuple) -> tuple:
        """
        Wyodrębnia klucz publiczny z klucza prywatnego.
        
        Klucz prywatny: (d, n)
        Klucz publiczny: (e, n) gdzie e to standardowo 65537
        
        Zwraca: tuple (e, n) lub raises ValueError
        """
        if not isinstance(private_key, tuple) or len(private_key) != 2:
            raise ValueError("Klucz prywatny musi być krotką (d, n)")
        
        d, n = private_key
        # Standardowa wartość e w RSA
        e = 65537
        return (e, n)
