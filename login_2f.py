import hashlib
import tkinter as tk
from tkinter import messagebox, simpledialog
import random
import time


# --- Funções de Hash e Verificação de Senha ---
def criar_hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()


def verificar_senha(senha_digitada, hash_armazenado):
    return criar_hash_senha(senha_digitada) == hash_armazenado


# --- Simulação de um banco de dados de usuários com níveis de acesso ---
# Adicionamos um campo para indicar se o 2FA está 'ativado' para o usuário
usuarios_bd = {
    "admin": {
        "hash_senha": criar_hash_senha("admin123"),
        "nivel_acesso": "admin",
        "2fa_ativado": True # 2FA ativado para admin
    },
    "editor": {
        "hash_senha": criar_hash_senha("editor123"),
        "nivel_acesso": "editor",
        "2fa_ativado": False # 2FA desativado para editor
    },
    "usuario": {
        "hash_senha": criar_hash_senha("user123"),
        "nivel_acesso": "user",
        "2fa_ativado": True # 2FA ativado para usuário
    },
    "dev": {
        "hash_senha": criar_hash_senha("devpass"),
        "nivel_acesso": "admin",
        "2fa_ativado": False # 2FA desativado para dev
    }
}

# Variáveis globais para armazenar o código OTP e o usuário em processo de 2FA
_otp_gerado = ""
_usuario_2fa = ""
_nivel_acesso_2fa = ""

# --- Lógica da Interface Gráfica (Tkinter) ---

def exibir_tela_principal(usuario_logado, nivel_acesso):
    """
    Cria e exibe uma nova janela simulando a tela principal do sistema,
    com base no nível de acesso do usuário.
    """
    tela_principal = tk.Toplevel(janela_login)
    tela_principal.title(f"Sistema - Logado como: {usuario_logado} ({nivel_acesso.upper()})")
    tela_principal.geometry("400x250")
    tela_principal.grab_set()

    tk.Label(tela_principal, text=f"Bem-vindo(a), {usuario_logado}!", font=("Arial", 14, "bold")).pack(pady=20)
    tk.Label(tela_principal, text=f"Seu nível de acesso é: {nivel_acesso.upper()}", font=("Arial", 12)).pack(pady=10)

    # Conteúdo específico por nível de acesso
    if nivel_acesso == "admin":
        tk.Label(tela_principal, text="Você tem acesso total: Gerenciar usuários, configurações, etc.").pack()
        tk.Button(tela_principal, text="Painel de Administração", command=lambda: messagebox.showinfo("Acesso", "Abrindo painel de administração...")).pack(pady=5)
    elif nivel_acesso == "editor":
        tk.Label(tela_principal, text="Você pode criar e editar conteúdo.").pack()
        tk.Button(tela_principal, text="Gerenciar Artigos", command=lambda: messagebox.showinfo("Acesso", "Abrindo gerenciador de artigos...")).pack(pady=5)
    elif nivel_acesso == "user":
        tk.Label(tela_principal, text="Você tem acesso básico para visualização.").pack()
        tk.Button(tela_principal, text="Ver Meu Perfil", command=lambda: messagebox.showinfo("Acesso", "Abrindo perfil do usuário...")).pack(pady=5)
    
    tk.Button(tela_principal, text="Logout", command=lambda: [tela_principal.destroy(), janela_login.deiconify()]).pack(pady=20)


def gerar_otp():
    """Gera um código OTP de 6 dígitos."""
    return str(random.randint(100000, 999999))

def verificar_otp_gui():
    """
    Exibe a janela para o usuário digitar o OTP e verifica.
    """
    global _otp_gerado, _usuario_2fa, _nivel_acesso_2fa

    # Gera um novo OTP para cada tentativa de 2FA
    _otp_gerado = gerar_otp()
    
    # Exibe o OTP para o usuário (simulando envio)
    messagebox.showinfo("Código 2FA (SIMULAÇÃO)", f"Seu código 2FA é: {_otp_gerado}\n(Este código expira em 60 segundos na vida real)")

    # Pede o código ao usuário
    otp_digitado = simpledialog.askstring("Verificação 2FA", "Digite o código 2FA:", parent=janela_login)

    if otp_digitado is None: # Se o usuário clicou em Cancelar
        messagebox.showerror("Login Cancelado", "Autenticação 2FA cancelada.")
        janela_login.deiconify() # Mostra a janela de login novamente
        entry_senha.delete(0, tk.END) # Limpa a senha
        entry_usuario.delete(0, tk.END) # Limpa o usuário
        entry_usuario.focus_set() # Retorna o foco
        return

    if otp_digitado == _otp_gerado:
        messagebox.showinfo("2FA Concluído", "Código 2FA verificado com sucesso!")
        # Se o OTP estiver correto, prossegue para a tela principal
        exibir_tela_principal(_usuario_2fa, _nivel_acesso_2fa)
    else:
        messagebox.showerror("Erro 2FA", "Código 2FA inválido.")
        janela_login.deiconify() # Mostra a janela de login novamente
        entry_senha.delete(0, tk.END) # Limpa a senha
        entry_usuario.delete(0, tk.END) # Limpa o usuário
        entry_usuario.focus_set() # Retorna o foco


def tentar_login():
    """
    Função chamada quando o botão de login é clicado.
    Verifica as credenciais, verifica 2FA se ativado e exibe a tela principal.
    """
    global _usuario_2fa, _nivel_acesso_2fa

    usuario = entry_usuario.get()
    senha = entry_senha.get()

    if usuario in usuarios_bd:
        dados_usuario = usuarios_bd[usuario]
        hash_armazenado = dados_usuario["hash_senha"]
        nivel_acesso = dados_usuario["nivel_acesso"]
        two_fa_ativado = dados_usuario.get("2fa_ativado", False) # Pega o valor, padrão é False

        if verificar_senha(senha, hash_armazenado):
            if two_fa_ativado:
                # Se 2FA ativado, guarda as informações do usuário e inicia o processo de 2FA
                _usuario_2fa = usuario
                _nivel_acesso_2fa = nivel_acesso
                janela_login.withdraw() # Esconde a janela de login temporariamente
                verificar_otp_gui()
            else:
                # Se 2FA desativado, vai direto para a tela principal
                messagebox.showinfo("Login Bem-Sucedido", f"Usuário '{usuario}' autenticado com sucesso como '{nivel_acesso.upper()}'!")
                janela_login.withdraw()
                exibir_tela_principal(usuario, nivel_acesso)
                entry_senha.delete(0, tk.END)
                entry_usuario.delete(0, tk.END)
                entry_usuario.focus_set()
                
        else:
            messagebox.showerror("Erro de Login", "Usuário ou senha inválidos.")
            entry_senha.delete(0, tk.END)
            entry_usuario.delete(0, tk.END)
            entry_usuario.focus_set() # Retorna o foco
    else:
        messagebox.showerror("Erro de Login", "Usuário ou senha inválidos.")
        entry_senha.delete(0, tk.END)
        entry_usuario.delete(0, tk.END)
        entry_usuario.focus_set() # Retorna o foco


# --- Configuração da Janela Principal de Login ---
janela_login = tk.Tk()
janela_login.title("Tela de Login (2FA Ativado)")
janela_login.geometry("350x250")
janela_login.resizable(False, False)

# Centralizar a janela na tela
janela_login.update_idletasks()
width = janela_login.winfo_width()
height = janela_login.winfo_height()
x = (janela_login.winfo_screenwidth() // 2) - (width // 2)
y = (janela_login.winfo_screenheight() // 2) - (height // 2)
janela_login.geometry(f'{width}x{height}+{x}+{y}')

# --- Widgets da Interface ---
tk.Label(janela_login, text="Login do Sistema (com 2FA)", font=("Arial", 16, "bold")).pack(pady=15)

label_usuario = tk.Label(janela_login, text="Usuário:")
label_usuario.pack()
entry_usuario = tk.Entry(janela_login, width=35)
entry_usuario.pack(pady=5)
entry_usuario.focus_set()

label_senha = tk.Label(janela_login, text="Senha:")
label_senha.pack()
entry_senha = tk.Entry(janela_login, width=35, show="*")
entry_senha.pack(pady=5)

button_login = tk.Button(janela_login, text="Login", command=tentar_login, font=("Arial", 10, "bold"))
button_login.pack(pady=15)

# Vincula a tecla Enter ao botão de login
janela_login.bind('<Return>', lambda event=None: tentar_login())

# --- Iniciar o Loop Principal da Interface ---
janela_login.mainloop()