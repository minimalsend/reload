import base64
import json
import time
import requests
from flask import Flask, jsonify, request
from concurrent.futures import ThreadPoolExecutor, as_completed
import random

app = Flask(__name__)

# -------------------------------
# Funções auxiliares
# -------------------------------

def carregar_usuarios(arch):
    try:
        url = f"https://scvirtual.alphi.media/botsistem/sendlike/{arch}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Erro ao carregar usuários: {e}")
        return None

def carregar_tokens_existentes():
    """Carrega token_br.json"""
    try:
        url = "https://scvirtual.alphi.media/botsistem/sendlike/token_br.json"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Erro ao carregar token_br.json: {e}")
        return []

def decode_jwt(token):
    """Decodifica o payload do JWT, retornando dicionário ou None"""
    try:
        payload_part = token.split(".")[1]
        padded = payload_part + "=" * (-len(payload_part) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded)
        decoded_str = decoded_bytes.decode("utf-8")
        return json.loads(decoded_str)
    except Exception as e:
        print(f"Erro ao decodificar JWT: {e}")
        return None

def token_expirado(token, tolerancia=300):
    """Retorna True se o token expirou ou vai expirar em até 'tolerancia' segundos"""
    payload = decode_jwt(token)
    if not payload:
        return True
    exp = payload.get("exp")
    if not exp:
        return True
    agora = int(time.time())
    if exp > 1e12:  # caso venha em milissegundos
        exp = int(exp / 1000)
    return exp < (agora + tolerancia)

def autenticar(usuario):
    uid = usuario.get('uid')
    password = usuario.get('password')
    if not uid or not password:
        return None
    url = f"https://jwt-maker-danger.vercel.app/token?uid={uid}&password={password}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            token = response.json().get('token')
            if token:
                return {"uid": uid, "token": token}
    except requests.RequestException as e:
        print(f"[{uid}] Erro ao autenticar: {e}")
    return None

def enviar_token_php(uid, login, token):
    """ Envia token para endpoint PHP """
    url = "https://scvirtual.alphi.media/botsistem/sendlike/receber_token.php"
    payload = {"uid": uid, "token": token}
    if login:
        payload["login"] = login
    try:
        r = requests.post(url, data=payload, timeout=5)
        if r.status_code == 200:
            print(f"[{uid}] ✅ Token enviado/atualizado no PHP.")
        else:
            print(f"[{uid}] ⚠️ Erro ao enviar token: {r.status_code}")
    except Exception as e:
        print(f"[{uid}] ❌ Falha ao enviar token: {e}")

# -------------------------------
# Processamento principal
# -------------------------------

def atualizar_tokens(arch):
    usuarios = carregar_usuarios(arch)
    if not usuarios:
        return None

    tokens_existentes = carregar_tokens_existentes()
    mapa_tokens = {item["uid"]: item for item in tokens_existentes if "uid" in item}

    tokens_validos = []
    novos_tokens = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        for usuario in usuarios:
            uid = usuario.get("uid")
            if not uid:
                continue

            dado_existente = mapa_tokens.get(uid)
            login_existente = dado_existente.get("login") if dado_existente else None
            token_atual = dado_existente.get("token") if dado_existente else None

            if login_existente and token_atual and not token_expirado(token_atual):
                # Token válido
                tokens_validos.append({"uid": uid, "token": token_atual, "login": login_existente})
                print(f"[{uid}] 🔵 Token válido, mantido. Login: {login_existente}")
                enviar_token_php(uid, login_existente, token_atual)
            else:
                # Precisa autenticar (novo token ou token expirado)
                futures[executor.submit(autenticar, usuario)] = (uid, login_existente)

        for future in as_completed(futures):
            uid, login_existente = futures[future]
            resultado = future.result()
            if resultado:
                token = resultado["token"]
                login_final = login_existente or uid  # fallback se não tiver login
                novos_tokens.append({"uid": uid, "token": token, "login": login_final})
                enviar_token_php(uid, login_final, token)
                print(f"[{uid}] 🟢 Token renovado/adicionado. Login: {login_final}")

    todos_tokens = tokens_validos + novos_tokens
    random.shuffle(todos_tokens)

    return {
        "tokens": todos_tokens,
        "validos": len(tokens_validos),
        "renovados": len(novos_tokens),
        "count": len(todos_tokens)
    }

# -------------------------------
# Rotas Flask
# -------------------------------

@app.route('/')
def index():
    return "Servidor de tokens JWT inteligente."

@app.route('/get_tokens')
def get_tokens():
    arch = request.args.get('arch')
    if not arch:
        return jsonify({"status": "error", "message": "Parâmetro 'arch' é obrigatório"}), 400

    resultado = atualizar_tokens(arch)
    if resultado:
        return jsonify({"status": "success", **resultado})
    else:
        return jsonify({"status": "error", "message": "Nenhum usuário encontrado"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
