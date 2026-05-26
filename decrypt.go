// Descifrado de resultados de becas en Go.
//
// Lee becas-2026-cifrado.csv producido por encrypt.py y produce
// becas-2026-descifrado.csv con los resultados en claro.
//
// Formato del blob por fila: VI (12 B) + ciphertext (n B) + tag (16 B)
//
// Uso:
//   go run decrypt.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"os"
)

const (
	keyFile    = "key.bin"
	inputFile  = "becas-2026-cifrado.csv"
	outputFile = "becas-2026-descifrado.csv"
	viSize     = 12 // 96 bits, mismo tamaño que en encrypt.py
	tagSize    = 16 // 128 bits, tamaño estándar del tag GCM
	keySize    = 32 // AES-256
)

func loadKey() ([]byte, error) {
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("tamaño de clave inválido: %d (se esperaba %d)", len(key), keySize)
	}
	return key, nil
}

func decryptScholarshipResult(key, cedula, blob []byte) (string, error) {
	// El blob debe tener al menos el VI y el tag, aunque el ciphertext esté vacío
	if len(blob) < viSize+tagSize {
		return "", fmt.Errorf("blob demasiado corto: %d bytes", len(blob))
	}
	vi := blob[:viSize]
	ciphertext := blob[viSize:] // incluye los 16 bytes de tag al final

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Open verifica el tag GCM usando la cédula como AAD.
	// Si la cédula del CSV no coincide con la que se usó al cifrar, falla aquí.
	scholarshipResult, err := aesgcm.Open(nil, vi, ciphertext, cedula)
	if err != nil {
		return "", fmt.Errorf("fallo de autenticación: %w", err)
	}
	return string(scholarshipResult), nil
}

func main() {
	key, err := loadKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error cargando clave:", err)
		os.Exit(1)
	}

	fin, err := os.Open(inputFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer fin.Close()

	fout, err := os.Create(outputFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer fout.Close()

	reader := csv.NewReader(fin)
	writer := csv.NewWriter(fout)
	defer writer.Flush()

	// Descarta el encabezado de entrada y escribe el encabezado de salida
	if _, err := reader.Read(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	writer.Write([]string{"cedula", "resultado_beca"})

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		cedula := row[0]
		blob, err := base64.StdEncoding.DecodeString(row[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "base64:", err)
			os.Exit(1)
		}
		scholarshipResult, err := decryptScholarshipResult(key, []byte(cedula), blob)
		if err != nil {
			fmt.Fprintln(os.Stderr, "descifrado:", err)
			os.Exit(1)
		}
		writer.Write([]string{cedula, scholarshipResult})
	}
	fmt.Println("Descifrado completado:", outputFile)
}