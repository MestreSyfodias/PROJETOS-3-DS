# login_hash.py
# Versão segura utilizando hash de senhas

import hashlib
import os
import json
from getpass import getpass

def gerar_hash_senha(senha):
    """
    Gera um hash seguro da senha usando salt
    """
    # Gera um salt aleatório (16 bytes)
    salt = os.urandom(32)
    
    # Gera o hash usando PBKDF2 (mais seguro que hash simples)
    hash_senha = hashlib.pbkdf2_hmac(
        'sha256',  # Algoritmo de hash
        senha.encode('utf-8'),  # Senha em bytes
        salt,  # Salt
        100000  # Número de iterações
    )
    
    return salt + hash_senha  # Combina salt e hash

def verificar_senha(senha, hash_armazenado):
    """
    Verifica se a senha corresponde ao hash armazenado
    """
    # Extrai o salt (primeiros 32 bytes) e o hash original
    salt = hash_armazenado[:32]
    hash_original = hash_armazenado[32:]
    
    # Gera o hash da senha fornecida com o mesmo salt
    hash_tentativa = hashlib.pbkdf2_hmac(
        'sha256',
        senha.encode('utf-8'),
        salt,
        100000
    )
    
    # Compara os hashes
    return hash_tentativa == hash_original

def cadastrar_usuario(usuarios):
    """Função para cadastrar um novo usuário com hash"""
    print("\n--- CADASTRO DE USUÁRIO ---")
    usuario = input("Digite o nome de usuário: ")
    
    # Verifica se usuário já existe
    if usuario in usuarios:
        print("Usuário já existe!")
        return
    
    # Usa getpass para não mostrar a senha enquanto digita
    senha = getpass("Digite a senha: ")
    confirmar_senha = getpass("Confirme a senha: ")
    
    if senha != confirmar_senha:
        print("As senhas não coincidem!")
        return
    
    # Gera o hash da senha
    hash_senha = gerar_hash_senha(senha)
    
    # Armazena o hash em formato hexadecimal
    usuarios[usuario] = hash_senha.hex()
    salvar_dados(usuarios)
    print("Usuário cadastrado com sucesso!")

def fazer_login(usuarios):
    """Função para realizar o login com verificação de hash"""
    print("\n--- LOGIN ---")
    usuario = input("Digite o nome de usuário: ")
    senha = getpass("Digite a senha: ")
    
    # Verifica se usuário existe
    if usuario not in usuarios:
        print("Usuário ou senha incorretos!")
        return False
    
    # Converte o hash armazenado de volta para bytes
    hash_armazenado = bytes.fromhex(usuarios[usuario])
    
    # Verifica a senha
    if verificar_senha(senha, hash_armazenado):
        print(f"Login bem-sucedido! Bem-vindo, {usuario}!")
        return True
    else:
        print("Usuário ou senha incorretos!")
        return False

def salvar_dados(usuarios):
    """Salva os dados em arquivo JSON"""
    with open('usuarios_hash.json', 'w') as f:
        json.dump(usuarios, f)

def carregar_dados():
    """Carrega os dados do arquivo JSON"""
    try:
        with open('usuarios_hash.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def main():
    """Função principal do programa"""
    # Carrega usuários existentes
    usuarios = carregar_dados()
    
    while True:
        print("\n=== SISTEMA DE LOGIN COM HASH ===")
        print("1 - Cadastrar")
        print("2 - Login")
        print("3 - Listar usuários (apenas nomes)")
        print("4 - Sair")
        
        opcao = input("Escolha uma opção: ")
        
        if opcao == "1":
            cadastrar_usuario(usuarios)
        elif opcao == "2":
            fazer_login(usuarios)
        elif opcao == "3":
            print("\nUsuários cadastrados:")
            for usuario in usuarios.keys():
                print(f"- {usuario}")
        elif opcao == "4":
            print("Saindo...")
            break
        else:
            print("Opção inválida!")

if __name__ == "__main__":
    main()