from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import hashlib
import os
import base64
import json
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from django.conf import settings


# ─── RSA ────────────────────────────────────────────────────────────────────

def generar_par_llaves():
    """Genera un par de llaves RSA-4096. Retorna (privada_pem, publica_pem)."""
    key = RSA.generate(4096)
    privada = key.export_key().decode('utf-8')
    publica = key.publickey().export_key().decode('utf-8')
    return privada, publica


def generar_certificado(privada_pem: str, publica_pem: str, username: str):
    """
    Genera un certificado X.509 real (self-signed) para un usuario dado.
    Retorna (certificado_pem_str, expiracion_datetime)
    """
    # Parsear las llaves a objetos de cryptography
    private_key = serialization.load_pem_private_key(privada_pem.encode('utf-8'), password=None)
    public_key = serialization.load_pem_public_key(publica_pem.encode('utf-8'))
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Casa Monarca"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    
    # Validez de 1 año
    ahora = datetime.datetime.utcnow()
    expiracion = ahora + datetime.timedelta(days=365)
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        ahora
    ).not_valid_after(
        expiracion
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    return cert_pem, expiracion


def cifrar_llave_aes(llave_aes: bytes, llave_publica_pem: str) -> str:
    """Cifra la llave AES con RSA-4096 (llave pública). Retorna base64."""
    pub_key = RSA.import_key(llave_publica_pem)
    cipher  = PKCS1_OAEP.new(pub_key)
    llave_cifrada = cipher.encrypt(llave_aes)
    return base64.b64encode(llave_cifrada).decode('utf-8')


def descifrar_llave_aes(llave_cifrada_b64: str, llave_privada_pem: str) -> bytes:
    """Descifra la llave AES con RSA-4096 (llave privada)."""
    priv_key     = RSA.import_key(llave_privada_pem)
    cipher       = PKCS1_OAEP.new(priv_key)
    llave_cifrada = base64.b64decode(llave_cifrada_b64)
    return cipher.decrypt(llave_cifrada)


# ─── AES-256 ─────────────────────────────────────────────────────────────────

def cifrar_datos(datos: dict, llave_publica_pem: str) -> dict:
    """
    Cifra un diccionario de datos con AES-256-EAX.
    Retorna dict con: datos_cifrados, nonce, tag, llave_aes_cifrada
    """
    # 1. Generar llave AES aleatoria de 256 bits
    llave_aes = os.urandom(32)

    # 2. Cifrar los datos
    datos_json = json.dumps(datos, ensure_ascii=False).encode('utf-8')
    cipher     = AES.new(llave_aes, AES.MODE_EAX)
    datos_cifrados, tag = cipher.encrypt_and_digest(datos_json)

    # 3. Cifrar la llave AES con RSA
    llave_aes_cifrada = cifrar_llave_aes(llave_aes, llave_publica_pem)

    return {
        'datos_cifrados'   : base64.b64encode(datos_cifrados).decode('utf-8'),
        'nonce'            : base64.b64encode(cipher.nonce).decode('utf-8'),
        'tag'              : base64.b64encode(tag).decode('utf-8'),
        'llave_aes_cifrada': llave_aes_cifrada,
    }


def descifrar_datos(paquete: dict, llave_privada_pem: str) -> dict:
    """
    Descifra un paquete cifrado. Retorna el diccionario original.
    """
    llave_aes     = descifrar_llave_aes(paquete['llave_aes_cifrada'], llave_privada_pem)
    datos_cifrados = base64.b64decode(paquete['datos_cifrados'])
    nonce          = base64.b64decode(paquete['nonce'])
    tag            = base64.b64decode(paquete['tag'])

    cipher = AES.new(llave_aes, AES.MODE_EAX, nonce=nonce)
    datos_json = cipher.decrypt_and_verify(datos_cifrados, tag)
    return json.loads(datos_json.decode('utf-8'))


# ─── SHA-256 ──────────────────────────────────────────────────────────────────

def calcular_hash(datos: str) -> str:
    """Calcula SHA-256 de un string. Retorna hex de 64 chars."""
    return hashlib.sha256(datos.encode('utf-8')).hexdigest()


# ─── FIRMA DIGITAL ───────────────────────────────────────────────────────────

def firmar(datos: str, llave_privada_pem: str) -> str:
    """Firma un string con RSA-4096 + SHA-256. Retorna base64."""
    priv_key = RSA.import_key(llave_privada_pem)
    h        = SHA256.new(datos.encode('utf-8'))
    firma    = pkcs1_15.new(priv_key).sign(h)
    return base64.b64encode(firma).decode('utf-8')


def verificar_firma(datos: str, firma_b64: str, llave_publica_pem: str) -> bool:
    """Verifica una firma digital. Retorna True si es válida."""
    try:
        pub_key = RSA.import_key(llave_publica_pem)
        h       = SHA256.new(datos.encode('utf-8'))
        pkcs1_15.new(pub_key).verify(h, base64.b64decode(firma_b64))
        return True
    except (ValueError, TypeError):
        return False

# ─── CIFRADO TRANSPARENTE DE BD (AES derivado de SECRET_KEY) ─────────────────

def _get_db_key() -> bytes:
    """Deriva una llave AES-256 (32 bytes) a partir del SECRET_KEY de Django."""
    sk = settings.SECRET_KEY.encode('utf-8')
    return hashlib.sha256(sk).digest()

def encriptar_valor_db(valor: str) -> str:
    """
    Encripta un valor en texto plano usando AES-GCM con llave de servidor.
    Retorna cadena codificada en base64 para almacenar en la BD.
    Incluye nonce y tag junto al ciphertext: base64(nonce + tag + ciphertext)
    """
    if valor is None or valor == "":
        return valor
    llave = _get_db_key()
    cipher = AES.new(llave, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(valor.encode('utf-8'))
    # Concatenamos nonce (16 bytes) + tag (16 bytes) + ciphertext
    paquete = cipher.nonce + tag + ciphertext
    return base64.b64encode(paquete).decode('utf-8')

def desencriptar_valor_db(paquete_b64: str) -> str:
    """
    Desencripta un valor almacenado en la BD a texto plano.
    """
    if paquete_b64 is None or paquete_b64 == "":
        return paquete_b64
    llave = _get_db_key()
    try:
        paquete = base64.b64decode(paquete_b64)
        nonce = paquete[:16]
        tag = paquete[16:32]
        ciphertext = paquete[32:]
        cipher = AES.new(llave, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except Exception:
        # En caso de error o datos no cifrados (código legacy), retornamos tal cual
        return paquete_b64