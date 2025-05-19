from flask import Flask, render_template, request, session, redirect, url_for, abort
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import secrets
import bcrypt

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Chave secreta para sessões (em produção, use uma chave fixa e segura!)

# Configurações de segurança (em produção, use um banco de dados!)
USUARIO_VALIDO = "admin"
SENHA_HASH = bcrypt.hashpw(b"senha_segura123", bcrypt.gensalt())  # Gere isso uma vez com: bcrypt.hashpw(b"sua_senha", bcrypt.gensalt())

# Chave AES-256 fixa (para demonstração; em produção, armazene com segurança!)
CHAVE = os.urandom(32)

def generate_csrf_token():
    """Gera um token CSRF único por sessão."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

# --- Rotas ---
@app.route('/')
def home():
    """Redireciona para a página de login ou criptografia."""
    if 'usuario' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login com validação de credenciais."""
    if 'usuario' in session:
        return redirect(url_for('index'))

    erro = None
    if request.method == 'POST':
        # Verifica token CSRF
        if request.form.get('csrf_token') != session.get('csrf_token'):
            abort(403)

        usuario = request.form.get('usuario')
        senha = request.form.get('senha').encode('utf-8')

        # Validação segura com bcrypt
        if usuario == USUARIO_VALIDO and bcrypt.checkpw(senha, SENHA_HASH):
            session['usuario'] = usuario
            session.permanent = True  # Sessão persistente
            return redirect(url_for('index'))
        else:
            erro = "Usuário ou senha inválidos."

    return render_template('login.html', erro=erro, csrf_token=generate_csrf_token())

@app.route('/logout')
def logout():
    """Encerra a sessão do usuário."""
    session.clear()
    return redirect(url_for('login'))

@app.route('/criptografia', methods=['GET', 'POST'])
def index():
    """Página principal de criptografia/descriptografia."""
    if 'usuario' not in session:
        return redirect(url_for('login'))

    resultado = None
    erro = None

    if request.method == 'POST':
        # Verifica token CSRF
        if request.form.get('csrf_token') != session.get('csrf_token'):
            abort(403)

        acao = request.form.get('acao')
        texto = request.form.get('texto', '').encode()

        try:
            if acao == 'criptografar':
                # Aplica padding PKCS#7
                padder = padding.PKCS7(128).padder()
                texto_padded = padder.update(texto) + padder.finalize()

                # Criptografia AES-256-CBC
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(CHAVE), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(texto_padded) + encryptor.finalize()

                # Codifica IV + ciphertext em Base64
                iv_ciphertext = iv + ciphertext
                resultado = base64.b64encode(iv_ciphertext).decode()

            elif acao == 'descriptografar':
                # Decodifica Base64 e separa IV/ciphertext
                iv_ciphertext = base64.b64decode(texto)
                iv = iv_ciphertext[:16]
                ciphertext = iv_ciphertext[16:]

                # Descriptografia AES-256-CBC
                cipher = Cipher(algorithms.AES(CHAVE), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                texto_decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

                # Remove padding
                unpadder = padding.PKCS7(128).unpadder()
                resultado = unpadder.update(texto_decrypted_padded) + unpadder.finalize()
                resultado = resultado.decode()

        except Exception as e:
            erro = f"Erro: {str(e)}"

    return render_template('index.html', 
                         resultado=resultado, 
                         erro=erro,
                         csrf_token=generate_csrf_token())

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')  # Debug desligado para produção!