# login_db.py
# Versão com banco de dados SQLite

import sqlite3
import hashlib
import os
from getpass import getpass

class SistemaLoginDB:
    def __init__(self, db_name='usuarios.db'):
        """Inicializa a conexão com o banco de dados"""
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.criar_tabela()
    
    def criar_tabela(self):
        """Cria a tabela de usuários se não existir"""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                hash_senha TEXT NOT NULL,
                data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()
    
    def gerar_hash(self, senha):
        """Gera salt e hash para a senha"""
        salt = os.urandom(32).hex()
        hash_senha = hashlib.pbkdf2_hmac(
            'sha256',
            senha.encode('utf-8'),
            bytes.fromhex(salt),
            100000
        ).hex()
        return salt, hash_senha
    
    def verificar_senha(self, senha, salt, hash_armazenado):
        """Verifica se a senha está correta"""
        hash_tentativa = hashlib.pbkdf2_hmac(
            'sha256',
            senha.encode('utf-8'),
            bytes.fromhex(salt),
            100000
        ).hex()
        return hash_tentativa == hash_armazenado
    
    def cadastrar_usuario(self):
        """Cadastra um novo usuário"""
        print("\n--- CADASTRO DE USUÁRIO ---")
        usuario = input("Digite o nome de usuário: ")
        
        # Verifica se usuário já existe
        self.cursor.execute(
            "SELECT usuario FROM usuarios WHERE usuario = ?", 
            (usuario,)
        )
        if self.cursor.fetchone():
            print("Usuário já existe!")
            return
        
        senha = getpass("Digite a senha: ")
        confirmar = getpass("Confirme a senha: ")
        
        if senha != confirmar:
            print("As senhas não coincidem!")
            return
        
        # Gera salt e hash
        salt, hash_senha = self.gerar_hash(senha)
        
        # Insere no banco de dados
        self.cursor.execute(
            "INSERT INTO usuarios (usuario, salt, hash_senha) VALUES (?, ?, ?)",
            (usuario, salt, hash_senha)
        )
        self.conn.commit()
        print("Usuário cadastrado com sucesso!")
    
    def fazer_login(self):
        """Realiza o login do usuário"""
        print("\n--- LOGIN ---")
        usuario = input("Digite o nome de usuário: ")
        senha = getpass("Digite a senha: ")
        
        # Busca usuário no banco
        self.cursor.execute(
            "SELECT salt, hash_senha FROM usuarios WHERE usuario = ?",
            (usuario,)
        )
        resultado = self.cursor.fetchone()
        
        if not resultado:
            print("Usuário ou senha incorretos!")
            return False
        
        salt, hash_armazenado = resultado
        
        if self.verificar_senha(senha, salt, hash_armazenado):
            print(f"Login bem-sucedido! Bem-vindo, {usuario}!")
            return True
        else:
            print("Usuário ou senha incorretos!")
            return False
    
    def listar_usuarios(self):
        """Lista todos os usuários cadastrados"""
        self.cursor.execute("SELECT usuario, data_criacao FROM usuarios")
        usuarios = self.cursor.fetchall()
        
        print("\n=== USUÁRIOS CADASTRADOS ===")
        for usuario, data in usuarios:
            print(f"Usuário: {usuario} - Criado em: {data}")
    
    def fechar_conexao(self):
        """Fecha a conexão com o banco de dados"""
        self.conn.close()

def main():
    """Função principal"""
    sistema = SistemaLoginDB()
    
    try:
        while True:
            print("\n=== SISTEMA DE LOGIN COM BANCO DE DADOS ===")
            print("1 - Cadastrar")
            print("2 - Login")
            print("3 - Listar usuários")
            print("4 - Sair")
            
            opcao = input("Escolha uma opção: ")
            
            if opcao == "1":
                sistema.cadastrar_usuario()
            elif opcao == "2":
                sistema.fazer_login()
            elif opcao == "3":
                sistema.listar_usuarios()
            elif opcao == "4":
                print("Saindo...")
                break
            else:
                print("Opção inválida!")
    finally:
        sistema.fechar_conexao()

if __name__ == "__main__":
    main()