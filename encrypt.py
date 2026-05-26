"""
Cifrado de resultados de becas con AES-256-GCM.
 
Formato del archivo de salida (CSV):
    cedula, cifrado_resultado_beca
donde cifrado_resultado_beca es base64( VI + ciphertext + tag ) -> concatenación, no suma bit a bit.
 
  - VI:         12 bytes (96 bits), aleatorio por fila
  - ciphertext: 
  - tag:        16 bytes (autenticación GCM)
 
La cédula viaja en texto plano, pero se incluye como AAD (Additional Authenticated
Data), por lo que su valor queda autenticado: alterar la cédula o
intercambiar dos filas hace fallar la verificación del tag en el descifrado.
"""
 
import csv
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
 
KEY_FILE    = "key.bin"
INPUT_FILE  = "becas-2026-plain.csv"
OUTPUT_FILE = "becas-2026-cifrado.csv"
 
KEY_BITS    = 256   # 256 bits (32 bytes),
VI_SIZE     = 12    # 96 bits (12 bytes), recomendado por NIST para GCM.
 
 
def generate_key() -> bytes:
    # AES-256: clave de 32 bytes obtenida del CSPRNG
    # (Generador de números pseudoaleatorios criptográficamente seguro) del sistema.
    key = AESGCM.generate_key(bit_length=KEY_BITS)
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key
 
 
def load_key() -> bytes:
    with open(KEY_FILE, "rb") as f:
        return f.read()
 
 
def encrypt_scholarship_result(key: bytes, cedula: str, scholarship_result: str) -> bytes:
    # VI único por cifrado: requisito absoluto de GCM.
    # Reusar (key, VI) con plaintexts distintos rompe confidencialidad
    # y permite forjar tags. Por eso lo generamos aleatorio cada vez.
    aesgcm = AESGCM(key)
    vi = os.urandom(VI_SIZE)
    aad = cedula.encode("utf-8")
    
    # encrypt() devuelve ciphertext + tag (16 bytes al final)
    # concatenación, no suma bit a bit.
    ciphertext_tag = aesgcm.encrypt(vi, scholarship_result.encode("utf-8"), aad)
    
    # Hay que brindar el VI porque sino el receptor no puede descifrar.
    # concatenación, no suma bit a bit.
    return vi + ciphertext_tag
 

def encrypt_file(key: bytes) -> None:
    with open(INPUT_FILE, newline="", encoding="utf-8") as fin, \
         open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as fout:
             
        reader = csv.reader(fin)
        writer = csv.writer(fout)
        
        next(reader)  # descarta el encabezado de entrada
        writer.writerow(["cedula", "cifrado_resultado_beca"])
        
        for row in reader:
            cedula, scholarship_result = row[0], row[1]
            blob = encrypt_scholarship_result(key, cedula, scholarship_result)
            writer.writerow([cedula, base64.b64encode(blob).decode("ascii")])
 
 
if __name__ == "__main__":
    key = load_key() if os.path.exists(KEY_FILE) else generate_key()
    encrypt_file(key)
    print(f"Cifrado completado: {OUTPUT_FILE}")