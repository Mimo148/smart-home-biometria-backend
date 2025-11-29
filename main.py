from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from deepface import DeepFace
import numpy as np
import os
import shutil
import uuid

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------
# APP + CORS
# ---------------------------------------------------------

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],  # alebo ["*"] na úplne voľný prístup
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# ZÁKLADNÉ CESTY A DÁTA
# ---------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# biometrická šablóna majiteľa
TEMPLATE_PATH = os.path.join(BASE_DIR, "templates", "owner2.npy")
owner_template = np.load(TEMPLATE_PATH)  # načítame pri štarte servera

# RSA kľúče pre E2E šifrovanie (hybrid: RSA + AES)
KEY_DIR = os.path.join(BASE_DIR, "keys")

with open(os.path.join(KEY_DIR, "public.pem"), "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

with open(os.path.join(KEY_DIR, "private.pem"), "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# stav dverí (smart lock simulácia)
door_unlocked = False  # na začiatku sú zamknuté


# ---------------------------------------------------------
# POMOCNÉ FUNKCIE
# ---------------------------------------------------------

def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Kosínová podobnosť dvoch vektorov."""
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    AES-256-CBC šifrovanie s jednoduchým PKCS7 paddingom.
    data: ľubovoľné bajty (embedding)
    key: 32 bajtov (AES-256)
    iv: 16 bajtov
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len]) * pad_len
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    AES-256-CBC dešifrovanie + odstránenie PKCS7 paddingu.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len]


# ---------------------------------------------------------
# ENDPOINTY
# ---------------------------------------------------------

@app.get("/")
def root():
    return {"message": "Biometricka autentifikacia pre inteligentnu domacnost bezi 🙂"}


@app.get("/door-status")
def door_status():
    """
    Vráti aktuálny stav dverí (smart lock).
    """
    status = "UNLOCKED" if door_unlocked else "LOCKED"
    return {
        "door_unlocked": bool(door_unlocked),
        "status": status,
    }


@app.post("/lock-door")
def lock_door():
    """
    Manuálne zamkne dvere.
    """
    global door_unlocked
    door_unlocked = False
    return {
        "door_unlocked": False,
        "status": "LOCKED",
    }


@app.post("/verify-face")
async def verify_face(file: UploadFile = File(...)):
    """
    Prijme obrázok tváre, spraví biometrický embedding,
    zašifruje ho hybridne (AES + RSA), potom na "auth serveri"
    dešifruje embedding a porovná ho so šablónou majiteľa.
    Podľa výsledku odomkne / zamkne dvere.
    """
    global door_unlocked

    # 1) dočasne uložíme prijatý obrázok
    temp_filename = f"temp_{uuid.uuid4().hex}.jpg"
    temp_path = os.path.join(BASE_DIR, temp_filename)

    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        # 2) vygenerujeme embedding z obrázka (biometrická šablóna)
        result = DeepFace.represent(img_path=temp_path, model_name="Facenet")[0]
        test_template = np.array(result["embedding"], dtype=np.float64)

        # -----------------------------------------------------
        # HYBRIDNÉ E2E ŠIFROVANIE
        # -----------------------------------------------------
        # Embedding -> bytes
        embedding_bytes = test_template.tobytes()

        # 3) náhodný AES kľúč a IV (symetrická časť E2E)
        aes_key = os.urandom(32)  # 32 bajtov = AES-256
        iv = os.urandom(16)       # 16 bajtov pre CBC mód

        # 4) AES-256-CBC zašifruje embedding
        encrypted_embedding = aes_encrypt(embedding_bytes, aes_key, iv)

        # 5) RSA public key zašifruje iba AES kľúč
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # --- v realite by sa toto poslalo cez sieť:
        # klient -> (encrypted_embedding, encrypted_aes_key, iv) -> auth server

        # 6) Auth server: RSA private key dešifruje AES kľúč
        decrypted_aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # 7) Auth server: AES dešifruje embedding
        decrypted_bytes = aes_decrypt(encrypted_embedding, decrypted_aes_key, iv)
        decrypted_template = np.frombuffer(decrypted_bytes, dtype=np.float64)

        # kontrola, či sa embedding po encrypt+decrypt nezmenil
        same_templates = bool(np.allclose(test_template, decrypted_template))

        # -----------------------------------------------------
        # BIOMETRICKÉ POROVNANIE
        # -----------------------------------------------------
        similarity = cosine_similarity(owner_template, decrypted_template)
        THRESHOLD = 0.7
        match = similarity > THRESHOLD

        # 8) podľa výsledku upravíme stav dverí
        if bool(match):
            door_unlocked = True
        else:
            door_unlocked = False

        status = "UNLOCKED" if door_unlocked else "LOCKED"

        return JSONResponse(
            content={
                "similarity": float(similarity),
                "threshold": float(THRESHOLD),
                "match": bool(match),
                "message": "MATCH" if bool(match) else "NO_MATCH",
                "door_unlocked": bool(door_unlocked),
                "door_status": status,
                # debug/info k šifrovaniu:
                "encryption_roundtrip_ok": same_templates,
            }
        )

    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"error": str(e)},
        )

    finally:
        # 9) zmažeme dočasný obrázok
        if os.path.exists(temp_path):
            os.remove(temp_path)
