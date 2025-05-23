import hashlib
import tkinter as tk
from tkinter import messagebox, simpledialog
import random
import json
import time
from datetime import datetime

# --- Configurações Globais ---
SECRET_KEY = "super_secreta_chave_para_token_e_auditoria" # Chave para "assinatura" de tokens e logs
LOG_FILE = "auditoria.log" # Arquivo para logs de auditoria

# --- Funções Auxiliares de Segurança ---
def criar_hash_senha(senha):
    """Cria um hash SHA256 da senha."""
    return hashlib.sha256(senha.encode()).hexdigest()

def verificar_senha(senha_digitada, hash_armazenado):
    """Verifica se a senha digitada corresponde ao hash armazenado."""
    return criar_hash_senha(senha_digitada) == hash_armazenado

def gerar_otp():
    """Gera um código OTP de 6 dígitos."""
    return str(random.randint(100000, 999999))

def sign_payload(payload):
    """Simula a assinatura de um payload (como um JWT)."""
    payload_str = json.dumps(payload, sort_keys=True) # Garante ordem consistente para hash
    return hashlib.sha256((payload_str + SECRET_KEY).encode()).hexdigest()

def verify_signature(payload, signature):
    """Verifica a assinatura de um payload."""
    expected_signature = sign_payload(payload)
    return signature == expected_signature

# --- Microsserviço Simulado: LoggerService (Monitoramento e Auditoria) ---
class LoggerService:
    """
    Simula um microsserviço de logging/auditoria.
    Registra eventos de acesso e operação em um arquivo de log.
    """
    def log_event(self, event_type, username, details, client_ip="127.0.0.1", status="SUCCESS"):
        timestamp = datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "username": username,
            "client_ip": client_ip,
            "details": details,
            "status": status,
            "signature": "" # Será assinado
        }
        # Assina o log para garantir integridade (simulado)
        log_entry["signature"] = sign_payload(log_entry)

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        print(f"[LoggerService] Logged: {event_type} for {username} - Status: {status}")

    def verify_log_integrity(self):
        """Verifica a integridade dos logs no arquivo."""
        print(f"\n[LoggerService] Verificando integridade dos logs em '{LOG_FILE}'...")
        corrupted_logs = []
        try:
            with open(LOG_FILE, "r") as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        log_entry = json.loads(line.strip())
                        if "signature" not in log_entry:
                            corrupted_logs.append(f"Linha {line_num}: Sem assinatura.")
                            continue

                        original_signature = log_entry["signature"]
                        # Remove a assinatura para recalcular
                        log_entry_without_signature = log_entry.copy()
                        del log_entry_without_signature["signature"]

                        if not verify_signature(log_entry_without_signature, original_signature):
                            corrupted_logs.append(f"Linha {line_num}: Assinatura inválida.")
                    except json.JSONDecodeError:
                        corrupted_logs.append(f"Linha {line_num}: Formato JSON inválido.")
            
            if corrupted_logs:
                print("Logs corrompidos ou adulterados encontrados:")
                for log in corrupted_logs:
                    print(f"- {log}")
                messagebox.showerror("Auditoria de Logs", "Foram detectados logs corrompidos ou adulterados. Verifique o console.")
            else:
                print("Todos os logs verificados com sucesso. Nenhuma corrupção detectada.")
                messagebox.showinfo("Auditoria de Logs", "Todos os logs verificados com sucesso. Nenhuma corrupção detectada.")
        except FileNotFoundError:
            print(f"Arquivo de log '{LOG_FILE}' não encontrado.")
            messagebox.showinfo("Auditoria de Logs", "Arquivo de log não encontrado.")
        except Exception as e:
            print(f"Erro ao verificar logs: {e}")
            messagebox.showerror("Auditoria de Logs", f"Erro ao verificar logs: {e}")

# --- Microsserviço Simulado: UserService (Gestão de Usuários) ---
_users_data = {
    "admin": {
        "hash_senha": criar_hash_senha("admin123"),
        "roles": ["admin", "user"],
        "2fa_ativado": True
    },
    "editor": {
        "hash_senha": criar_hash_senha("editor123"),
        "roles": ["editor", "user"],
        "2fa_ativado": False
    },
    "cliente": {
        "hash_senha": criar_hash_senha("cliente123"),
        "roles": ["client"],
        "2fa_ativado": True
    },
    "gerente": {
        "hash_senha": criar_hash_senha("gerente123"),
        "roles": ["manager", "editor"],
        "2fa_ativado": False
    }
}

class UserService:
    def __init__(self, logger):
        self.logger = logger

    def get_user_data(self, username):
        self.logger.log_event("USER_QUERY", username, f"Consulta de dados para usuário: {username}")
        return _users_data.get(username)

# --- Microsserviço Simulado: AuthService (Servidor de Autenticação) ---
class AuthService:
    def __init__(self, user_service, logger):
        self.user_service = user_service
        self.logger = logger

    def authenticate(self, username, password, client_ip="127.0.0.1"):
        user_data = self.user_service.get_user_data(username)

        if not user_data:
            self.logger.log_event("LOGIN_ATTEMPT", username, "Usuário não encontrado.", client_ip=client_ip, status="FAILED")
            return None, False, "Usuário não encontrado."

        if verificar_senha(password, user_data["hash_senha"]):
            # Gera um JWT simplificado
            payload = {
                "user": username,
                "roles": user_data["roles"],
                "2fa_required": user_data.get("2fa_ativado", False),
                "exp": int(time.time()) + 3600 # Token expira em 1 hora (simulado)
            }
            token = {"payload": payload, "signature": sign_payload(payload)}
            
            self.logger.log_event("LOGIN_ATTEMPT", username, "Autenticação primária bem-sucedida.", client_ip=client_ip, status="SUCCESS")
            return token, user_data.get("2fa_ativado", False), "Autenticação primária bem-sucedida."
        else:
            self.logger.log_event("LOGIN_ATTEMPT", username, "Senha incorreta.", client_ip=client_ip, status="FAILED")
            return None, False, "Credenciais inválidas."

# --- Microsserviço Simulado: OrderService (Gestão de Pedidos) ---
class OrderService:
    def __init__(self, logger):
        self.logger = logger
        # Simula alguns pedidos para exemplo
        self.orders = {
            "order_001": {"item": "Laptop", "value": 1200, "status": "Pending", "owner": "cliente"},
            "order_002": {"item": "Mouse", "value": 50, "status": "Completed", "owner": "admin"}
        }

    def _authorize(self, token_payload, required_roles, action="access"):
        """Verifica se o token tem as roles necessárias."""
        user_roles = token_payload.get("roles", [])
        username = token_payload.get("user", "UNKNOWN")

        if not any(role in user_roles for role in required_roles):
            self.logger.log_event("AUTHORIZATION_DENIED", username,
                                  f"Tentativa de {action} sem roles necessárias: {required_roles}",
                                  status="DENIED")
            return False
        return True

    def get_all_orders(self, token, client_ip="127.0.0.1"):
        # O AppService real validaria o token antes de chamar este método.
        # Aqui, validamos o token dentro do serviço para simular a proteção de endpoint.
        is_valid, payload = app_service.validate_token(token)
        if not is_valid:
            self.logger.log_event("API_ACCESS_DENIED", "UNKNOWN_USER", f"Acesso negado a get_all_orders: {payload}", client_ip=client_ip, status="DENIED")
            return {"error": "Token inválido ou expirado", "details": payload}, "DENIED"

        if not self._authorize(payload, ["admin", "manager"], "get_all_orders"):
            return {"error": "Acesso negado. Requer roles: Admin ou Gerente."}, "DENIED"
        
        self.logger.log_event("API_ACCESS_GRANTED", payload["user"], "Acesso a get_all_orders.", client_ip=client_ip, status="SUCCESS")
        return self.orders, "SUCCESS"

    def create_order(self, token, order_data, client_ip="127.0.0.1"):
        is_valid, payload = app_service.validate_token(token)
        if not is_valid:
            self.logger.log_event("API_ACCESS_DENIED", "UNKNOWN_USER", f"Acesso negado a create_order: {payload}", client_ip=client_ip, status="DENIED")
            return {"error": "Token inválido ou expirado"}, "DENIED"

        if not self._authorize(payload, ["client", "admin", "manager"], "create_order"):
            return {"error": "Acesso negado. Requer roles: Cliente, Admin ou Gerente."}, "DENIED"
        
        new_order_id = f"order_{len(self.orders) + 1:03d}"
        self.orders[new_order_id] = {**order_data, "owner": payload["user"], "status": "Pending"}
        self.logger.log_event("ORDER_CREATED", payload["user"], f"Novo pedido criado: {new_order_id}", client_ip=client_ip, status="SUCCESS")
        return {"message": "Pedido criado com sucesso", "order_id": new_order_id}, "SUCCESS"


# --- Microsserviço Simulado: AppService (Gateway/Recursos Protegidos) ---
# Em uma arquitetura real, este seria o ponto de entrada para a maioria das requisições do cliente
# e orquestraria chamadas a outros microsserviços.
class AppService:
    def __init__(self, user_service, logger):
        self.user_service = user_service
        self.logger = logger

    def validate_token(self, token, client_ip="127.0.0.1"):
        """Valida o token JWT simplificado."""
        if not token or "payload" not in token or "signature" not in token:
            self.logger.log_event("TOKEN_VALIDATION_FAILED", "UNKNOWN_USER", "Token malformado ou ausente.", client_ip=client_ip, status="FAILED")
            return False, "Token inválido ou malformado."

        payload = token["payload"]
        signature = token["signature"]
        username = payload.get("user", "UNKNOWN")

        if not verify_signature(payload, signature):
            self.logger.log_event("TOKEN_VALIDATION_FAILED", username, "Assinatura do token inválida.", client_ip=client_ip, status="FAILED")
            return False, "Assinatura do token inválida."
        
        # Verifica a expiração
        if payload.get("exp", 0) < int(time.time()):
            self.logger.log_event("TOKEN_VALIDATION_FAILED", username, "Token expirado.", client_ip=client_ip, status="FAILED")
            return False, "Token expirado."

        # Verifica se o usuário do token ainda existe no UserService (simulando revogação, etc.)
        user_data = self.user_service.get_user_data(username)
        if not user_data:
            self.logger.log_event("TOKEN_VALIDATION_FAILED", username, "Usuário do token não encontrado ou revogado.", client_ip=client_ip, status="FAILED")
            return False, "Usuário do token não encontrado ou revogado."

        self.logger.log_event("TOKEN_VALIDATION_SUCCESS", username, "Token validado com sucesso.", client_ip=client_ip, status="SUCCESS")
        return True, payload

# --- Inicialização dos "Microsserviços" ---
logger_service = LoggerService()
user_service = UserService(logger_service)
auth_service = AuthService(user_service, logger_service)
app_service = AppService(user_service, logger_service)
order_service = OrderService(logger_service) # Novo serviço de pedidos

# --- Variáveis Globais para o Estado da GUI ---
_otp_gerado = ""
_current_session_token = None # Armazena o token após o login completo
_client_ip = "192.168.1.100" # IP simulado do cliente mobile

# --- Funções da Interface Gráfica (Tkinter) ---

def exibir_tela_principal():
    """
    Cria e exibe uma nova janela simulando a tela principal do sistema,
    interagindo com o AppService e OrderService.
    """
    global _current_session_token

    if not _current_session_token:
        messagebox.showerror("Erro", "Nenhum token de sessão ativo.")
        janela_login.deiconify()
        return

    is_valid, payload = app_service.validate_token(_current_session_token, client_ip=_client_ip)
    if not is_valid:
        messagebox.showerror("Erro de Acesso", f"Sessão expirada ou inválida. Por favor, faça login novamente.")
        _current_session_token = None
        janela_login.deiconify()
        return

    usuario_logado = payload["user"]
    roles = payload["roles"]

    tela_principal = tk.Toplevel(janela_login)
    tela_principal.title(f"Sistema - Logado como: {usuario_logado} (Roles: {', '.join(roles)})")
    tela_principal.geometry("500x400")
    tela_principal.grab_set()

    tk.Label(tela_principal, text=f"Bem-vindo(a), {usuario_logado}!", font=("Arial", 16, "bold")).pack(pady=10)
    tk.Label(tela_principal, text=f"Suas roles: {', '.join(roles).upper()}", font=("Arial", 12)).pack(pady=5)

    # --- Seção de Gestão de Pedidos (Interage com OrderService) ---
    frame_pedidos = tk.LabelFrame(tela_principal, text="Gestão de Pedidos", padx=10, pady=10)
    frame_pedidos.pack(pady=15, fill="x", padx=20)

    # Botão para Listar Pedidos
    tk.Button(frame_pedidos, text="Listar Todos os Pedidos", 
              command=lambda: listar_pedidos_gui(tela_principal)).pack(pady=5)

    # Botão para Criar Pedido
    tk.Button(frame_pedidos, text="Criar Novo Pedido", 
              command=lambda: criar_pedido_gui(tela_principal)).pack(pady=5)

    # --- Seção de Auditoria (para Admin/Gerente) ---
    if "admin" in roles or "manager" in roles:
        frame_auditoria = tk.LabelFrame(tela_principal, text="Auditoria e Monitoramento", padx=10, pady=10)
        frame_auditoria.pack(pady=15, fill="x", padx=20)
        tk.Button(frame_auditoria, text="Verificar Integridade dos Logs", 
                  command=logger_service.verify_log_integrity).pack(pady=5)

    def fazer_logout():
        global _current_session_token
        logger_service.log_event("LOGOUT", usuario_logado, "Usuário desconectado.", client_ip=_client_ip)
        _current_session_token = None
        tela_principal.destroy()
        janela_login.deiconify()
        entry_senha.delete(0, tk.END)
        entry_usuario.delete(0, tk.END)
        entry_usuario.focus_set()

    tk.Button(tela_principal, text="Logout", command=fazer_logout, bg="red", fg="white").pack(pady=20)

def listar_pedidos_gui(parent_window):
    """Exibe os pedidos obtidos do OrderService."""
    response, status = order_service.get_all_orders(_current_session_token, client_ip=_client_ip)
    
    if status == "SUCCESS":
        orders_str = "\n".join([f"ID: {oid}, Item: {data['item']}, Status: {data['status']}" for oid, data in response.items()])
        messagebox.showinfo("Listagem de Pedidos", f"Pedidos:\n{orders_str}")
    else:
        messagebox.showerror("Erro ao Listar Pedidos", response["error"])

def criar_pedido_gui(parent_window):
    """Permite ao usuário criar um novo pedido."""
    item = simpledialog.askstring("Criar Pedido", "Qual item você deseja pedir?", parent=parent_window)
    if item:
        value = simpledialog.askfloat("Criar Pedido", f"Qual o valor de '{item}'?", parent=parent_window)
        if value is not None:
            order_data = {"item": item, "value": value}
            response, status = order_service.create_order(_current_session_token, order_data, client_ip=_client_ip)
            if status == "SUCCESS":
                messagebox.showinfo("Pedido Criado", response["message"] + f"\nID: {response['order_id']}")
            else:
                messagebox.showerror("Erro ao Criar Pedido", response["error"])
        else:
            messagebox.showinfo("Criação de Pedido", "Valor do item não fornecido. Operação cancelada.")
    else:
        messagebox.showinfo("Criação de Pedido", "Item não fornecido. Operação cancelada.")


def verificar_otp_gui(auth_token_from_2fa):
    """
    Exibe a janela para o usuário digitar o OTP e verifica.
    """
    global _otp_gerado, _current_session_token

    _otp_gerado = gerar_otp()
    
    messagebox.showinfo("Código 2FA (SIMULAÇÃO)", f"Seu código 2FA é: {_otp_gerado}\n(Este código expira em 60 segundos na vida real)")

    otp_digitado = simpledialog.askstring("Verificação 2FA", "Digite o código 2FA:", parent=janela_login)

    if otp_digitado is None:
        logger_service.log_event("2FA_CANCELED", auth_token_from_2fa["payload"]["user"], "Autenticação 2FA cancelada pelo usuário.", client_ip=_client_ip, status="FAILED")
        messagebox.showerror("Login Cancelado", "Autenticação 2FA cancelada.")
        janela_login.deiconify()
        entry_senha.delete(0, tk.END)
        entry_usuario.delete(0, tk.END)
        entry_usuario.focus_set()
        return

    if otp_digitado == _otp_gerado:
        logger_service.log_event("2FA_SUCCESS", auth_token_from_2fa["payload"]["user"], "Código 2FA verificado com sucesso.", client_ip=_client_ip, status="SUCCESS")
        messagebox.showinfo("2FA Concluído", "Código 2FA verificado com sucesso!")
        _current_session_token = auth_token_from_2fa
        exibir_tela_principal() # Agora só chama exibir_tela_principal
    else:
        logger_service.log_event("2FA_FAILED", auth_token_from_2fa["payload"]["user"], "Código 2FA inválido.", client_ip=_client_ip, status="FAILED")
        messagebox.showerror("Erro 2FA", "Código 2FA inválido.")
        janela_login.deiconify()
        entry_senha.delete(0, tk.END)
        entry_usuario.delete(0, tk.END)
        entry_usuario.focus_set()


def tentar_login():
    """
    Função principal da GUI para login.
    Interage com o AuthService para autenticar e, se necessário, com o 2FA.
    """
    global _current_session_token

    usuario = entry_usuario.get()
    senha = entry_senha.get()

    token, two_fa_required, message = auth_service.authenticate(usuario, senha, client_ip=_client_ip)

    if token:
        if two_fa_required:
            messagebox.showinfo("Autenticação Necessária", message + " Requer 2FA.")
            janela_login.withdraw()
            verificar_otp_gui(token)
        else:
            messagebox.showinfo("Login Bem-Sucedido", message)
            _current_session_token = token
            janela_login.withdraw()
            exibir_tela_principal()
    else:
        messagebox.showerror("Erro de Login", message)
        entry_senha.delete(0, tk.END)
        entry_usuario.delete(0, tk.END)
        entry_usuario.focus_set()


# --- Configuração da Janela Principal de Login ---
janela_login = tk.Tk()
janela_login.title("Simulação de Microsserviços e Segurança")
janela_login.geometry("380x280")
janela_login.resizable(False, False)

# Centralizar a janela na tela
janela_login.update_idletasks()
width = janela_login.winfo_width()
height = janela_login.winfo_height()
x = (janela_login.winfo_screenwidth() // 2) - (width // 2)
y = (janela_login.winfo_screenheight() // 2) - (height // 2)
janela_login.geometry(f'{width}x{height}+{x}+{y}')

# --- Widgets da Interface ---
tk.Label(janela_login, text="Sistema de Autenticação", font=("Arial", 16, "bold")).pack(pady=15)
tk.Label(janela_login, text="Usuário:").pack()
entry_usuario = tk.Entry(janela_login, width=35)
entry_usuario.pack(pady=5)
entry_usuario.focus_set()

tk.Label(janela_login, text="Senha:").pack()
entry_senha = tk.Entry(janela_login, width=35, show="*")
entry_senha.pack(pady=5)

button_login = tk.Button(janela_login, text="Login", command=tentar_login, font=("Arial", 10, "bold"))
button_login.pack(pady=15)

janela_login.bind('<Return>', lambda event=None: tentar_login())

# --- Iniciar o Loop Principal da Interface ---
janela_login.mainloop()