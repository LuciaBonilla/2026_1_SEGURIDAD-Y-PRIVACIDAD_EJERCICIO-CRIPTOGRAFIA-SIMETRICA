# 2026_1_SEGURIDAD-Y-PRIVACIDAD_EJERCICIO-CRIPTOGRAFIA-SIMETRICA
Ejercicio del curso de Seguridad y Privacidad sobre implementación de criptografía simétrica.

## Ejercicio

Debe cifrar un archivo CSV con los resultados de las becas para el 2026.

El archivo debe poseer la cédula de identidad del postulante y el resultado de
la beca. La cédulad de identidad debe estar en texto plano, y el resultado
de la beca cifrado de forma segura.

- Implementen un programa en Python para cifrar el archivo, y un programa
en otro lenguaje para descifrarlo.
- Tome en cuenta los principios de Kerckhoffs para su diseño e implentación.

## Resolución

No toda configuración de cifrado es igual de buena. Cada parámetro debe ser
seleccionado cuidadosamente.

- Algoritmo
- Modo de bloque
- Largo de clave
- Padding
- Vector de inicialización

Para este caso, seleccionamos:

- Algoritmo: AES, porque es el estándar actual y ha sido escrutado
públicamente durante más de dos décadas.
- Modo de bloque: GCM, porque combina confidencialidad, integridad y autenticación
en una sola operación.
- Largo de clave: 256 bits, porque ofrece una cantidad exponencialmente mayor de
permutaciones posibles, es decir, ofrece una mayor cantidad de claves que otros
largos de clave.

Nota. En AES hay dos arquitecturas:

- Arquitectura A — el plaintext entra a AES (ECB, CBC)
- Arquitectura B — un contador entra a AES, y el resultado se XORea
con el plaintext (CTR, OFB, CFB, GCM, CCM)

<img width="1280" height="1409" alt="image" src="https://github.com/user-attachments/assets/08170133-3867-455f-8fb4-abc0deff27be" />
Operación GCM. Para simplificar, se muestra un caso con un único bloque de datos
autenticados (denominado Auth Data 1) y dos bloques de texto plano.


- Padding: no aplica, porque el plaintext no entra nunca a AES. Lo que entra a AES
es una secuencia de contadores fabricados de 256 bits; cada invocación de AES
produce bloques de 256 bits. Luego los bloques son XOReados con el texto plano.
- Vector de inicialización: 96 bits aleatorio (os.urandom), el tamaño es recomendado
por NIST SP 800-38D para GCM.
- Additional Authenticated Data (necesario en GCM según NIST SP 800-38D): la cédula.

Nota. Additional Authenticated Data son los datos de entrada a la función de cifrado
autenticado que están autenticados, pero no cifrados.

## ¿Cómo se usa el código?

```python
pip install cryptography
python3 encrypt.py           # genera key.bin (primera vez) y becas-2026-encrypted.csv
go run decrypt.go            # produce becas-2026-decrypted.csv
```

https://pypi.org/project/cryptography/

https://cryptography.io/en/latest/

https://cryptography.io/en/latest/hazmat/primitives/aead/