from flask import Flask, jsonify, request
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random
from Crypto.Cipher import AES
import binascii
import my_pb2
import output_pb2
from colorama import init
import warnings
from urllib3.exceptions import InsecureRequestWarning
from requests.exceptions import RequestException
import logging
import asyncio
import httpx
from io import BytesIO
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from cachetools import TTLCache
from google.protobuf import json_format, message
from google.protobuf.message import Message
import base64
from flask_caching import Cache
from typing import Tuple, Optional
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timezone
from colorama import init
from urllib3.exceptions import InsecureRequestWarning
from protobuf_decoder.protobuf_decoder import Parser
from requests.exceptions import RequestException
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
app = Flask(__name__)

# Funções auxiliares
def carregar_usuarios(arch):
    try:
        url = f"https://scvirtual.alphi.media/botsistem/sendlike/{arch}"
        response = requests.get(url)
        response.raise_for_status()
        return response.json()  # Retorna os dados dos usuários
    except requests.RequestException as e:
        print(f"Erro ao carregar usuários: {e}")
        return None

def fetch_attversion():
    url = "https://raw.githubusercontent.com/minimalsend/release/refs/heads/main/version.json"  # Link com JSON simples

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        def buscar_attversion(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    if k == "attversion":
                        return v
                    resultado = buscar_attversion(v)
                    if resultado is not None:
                        return resultado
            elif isinstance(d, list):
                for item in d:
                    resultado = buscar_attversion(item)
                    if resultado is not None:
                        return resultado
            return None
        
        attversion = buscar_attversion(data)
        if attversion is not None:
            print(f"attversion: {attversion}")
            return attversion
        else:
            print("Parâmetro 'attversion' não encontrado.")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Erro na requisição: {e}")
    except ValueError:
        print("Erro ao decodificar o JSON.")
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()
def get_token(password, uid, max_retries=3):
    """
    Obtém token de autenticação da API Garena com proteção contra rate limiting.
    
    Args:
        password (str): Senha/Token de acesso
        uid (str/int): ID do usuário
        max_retries (int): Número máximo de tentativas em caso de erro
        
    Returns:
        dict: Dicionário com token e open_id em caso de sucesso, None em caso de falha
    """
    # Configurações da requisição
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "authority": "100067.connect.garena.com",
        "method": "GET",
        "scheme": "https",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        "cache-control": "max-age=0",
        "priority": "u=0, i",
        "sec-ch-ua": '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
    }
    data = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }

    # Tentativas com backoff exponencial
    for attempt in range(max_retries):
        try:
            # Delay progressivo entre tentativas
            if attempt > 0:
                wait_time = min((2 ** attempt) + random.uniform(0, 1), 10)  # Backoff exponencial com jitter
                print(f"Tentativa {attempt + 1}/{max_retries}. Aguardando {wait_time:.2f} segundos...")
                time.sleep(wait_time)

            # Faz a requisição
            res = requests.post(url, headers=headers, data=data, timeout=15)
            
            # Trata resposta
            if res.status_code == 200:
                token_json = res.json()
                if "access_token" in token_json and "open_id" in token_json:
                    return token_json
                else:
                    print("Resposta inválida: Token ou OpenID ausente")
                    continue
            
            # Trata rate limiting (429)
            elif res.status_code == 429:
                retry_after = res.headers.get('Retry-After', 5)  # Tenta obter tempo de espera do header
                print(f"Rate limit atingido. Servidor pede para esperar {retry_after} segundos.")
                time.sleep(float(retry_after))
                continue
            
            # Outros erros HTTP
            else:
                print(f"Erro HTTP {res.status_code}: {res.text}")
                continue

        except RequestException as e:
            print(f"Erro na requisição (tentativa {attempt + 1}): {str(e)}")
            continue
        
        except ValueError as e:
            print(f"Erro ao decodificar JSON (tentativa {attempt + 1}): {str(e)}")
            continue

    print(f"Falha após {max_retries} tentativas.")
    return None


def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)


def parse_response(content):
    response_dict = {}
    lines = content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

def get_single_response(uid: str, password: str) -> dict:
    """Get authentication token."""
    uid = uid
    password = password
    versionob = fetch_attversion()
    token_data = get_token(password, uid)
    if not token_data:
        raise ValueError("Failed to get token: Wrong UID or Password")

    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.108.3"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = token_data['open_id']
    game_data.access_token = token_data['access_token']
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    game_data.field_60 = 32968
    game_data.field_61 = 29815
    game_data.field_62 = 2479
    game_data.field_63 = 914
    game_data.field_64 = 31213
    game_data.field_65 = 32968
    game_data.field_66 = 31213
    game_data.field_67 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
    game_data.field_76 = 1
    game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
    game_data.field_78 = 6
    game_data.field_79 = 1
    game_data.os_architecture = "32"
    game_data.build_number = "2019117877"
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.field_92 = 9204
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
    game_data.total_storage = 111107
    game_data.field_97 = 1
    game_data.field_98 = 1
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    try:
        serialized_data = game_data.SerializeToString()
        encrypted_data = aes_cbc_encrypt(AES_KEY, AES_IV, serialized_data)
        edata = binascii.hexlify(encrypted_data).decode()

        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': f'{versionob}'
        }

        response = requests.post(
            "https://loginbp.common.ggbluefox.com/MajorLogin",
            data=bytes.fromhex(edata),
            headers=headers,
            verify=False
        )

        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            example_msg.ParseFromString(response.content)
            response_dict = parse_response(str(example_msg))
            
            return response_dict.get("token")
        
        raise ValueError(f"HTTP {response.status_code} - {response.reason}")

    except Exception as e:
        raise ValueError(f"Token generation failed: {str(e)}")
def autenticar(usuario):
    uid = usuario.get('uid')
    password = usuario.get('password')
    if not uid or not password:
        return None

    for attempt in range(1, 4):
        try:
            token = get_single_response(uid, password)

            if token:  # se não for None ou vazio
                return {"uid": uid, "token": token}
            else:
                print(f"[{uid}] Tentativa {attempt}/3 - Nenhum token recebido.")

        except Exception as e:
            print(f"[{uid}] Tentativa {attempt}/3 - Erro ao autenticar: {e}")

        time.sleep(0.2)

    print(f"[{uid}] ❌ Falha após 3 tentativas de autenticação.")
    return None



def atualizar_tokens(arch):
    usuarios = carregar_usuarios(arch)
    if not usuarios:
        return None
    usuarios = remover_duplicados_e_notificar(usuarios, arch)
    novos_tokens = []
    uids_processados = set()
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for usuario in usuarios:
            uid = usuario.get('uid')
            if uid and uid not in uids_processados:
                uids_processados.add(uid)
                futures.append(executor.submit(autenticar, usuario))
        
        for future in as_completed(futures):
            resultado = future.result()
            if resultado:
                novos_tokens.append({"token": resultado['token']})
                print(f"Token recebido para {resultado['uid']}")

    if novos_tokens:
        # Embaralha os tokens antes de retornar
        random.shuffle(novos_tokens)
        print(f"Total de tokens gerados: {len(novos_tokens)}")
        return novos_tokens
    return None

def remover_duplicados_e_notificar(usuarios, arch):
    vistos = set()
    unicos = []
    for user in usuarios:
        uid = user.get("uid")
        password = user.get("password")
        chave = (uid, password)
        if chave in vistos:
            reportar_duplicata(uid, password, arch)
        else:
            vistos.add(chave)
            unicos.append(user)
    return unicos

def reportar_duplicata(uid, password, arch):
    try:
        url = "https://scvirtual.alphi.media/botsistem/sendlike/delete_duplicate.php"
        payload = {
            "uid": uid,
            "password": password,
            "arch":arch
        }
        response = requests.post(url, data=payload, timeout=5)
        if response.status_code == 200:
            print(f"[{uid}] 🔴 Duplicata reportada e solicitada remoção.")
        else:
            print(f"[{uid}] ⚠️ Falha ao reportar duplicata. Status: {response.status_code}")
    except Exception as e:
        print(f"[{uid}] Erro ao tentar notificar o PHP: {e}")

# Rotas do Flask
@app.route('/')
def index():
    return "Servidor de tokens JWT. Use /get_tokens para recarregar e obter tokens ou /tokens?get-token=true para obter tokens novos."

@app.route('/get_tokens')
def get_tokens():
    arch = request.args.get('arch')
    tokens = atualizar_tokens(arch)
    if tokens:
        return jsonify({
            "status": "success",
            "message": "Tokens gerados com sucesso",
            "tokens": tokens,
            "count": len(tokens)
        })
    else:
        return jsonify({
            "status": "error",
            "message": "Falha ao gerar tokens"
        }), 500

@app.route('/tokens')
def gerenciar_tokens():
    get_update = request.args.get('get-update', '').lower() == 'true'
    get_token = request.args.get('get-token', '').lower() == 'true'
    arch = request.args.get('arch')
    
    if get_update or get_token:
        # Sempre gera novos tokens e não usa cache
        tokens = atualizar_tokens(arch)
        if tokens:
            return jsonify({"status": "success", "tokens": tokens, "count": len(tokens)})
        else:
            return jsonify({"status": "error", "message": "Falha ao gerar tokens"}), 500
    
    else:
        return jsonify({"status": "error", "message": "Parâmetro inválido. Use get-update=true ou get-token=true"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)

