// Package crypto предоставляет утилиты AES-256-GCM шифрования/дешифрования
// для текстовых данных и потокового шифрования медиа-файлов.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// ErrDecryptionFailed возвращается при ошибке дешифрования (неверный ключ или данные повреждены).
var ErrDecryptionFailed = errors.New("crypto: decryption failed")

// Cipher реализует AES-256-GCM шифрование.
type Cipher struct {
	key []byte // 32 байта
}

// NewCipher создаёт новый Cipher из 32-байтового ключа.
// Ключ должен быть получен из hex-строки через encoding/hex.DecodeString.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: ключ должен быть 32 байта, получено %d", len(key))
	}
	return &Cipher{key: key}, nil
}

// ─── Текстовое шифрование ────────────────────────────────────────────────────

// EncryptText шифрует plaintext с помощью AES-256-GCM.
// Возвращает base64(ciphertext+tag) и base64(nonce).
func (c *Cipher) EncryptText(plaintext []byte) (ciphertextB64, ivB64 string, err error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", "", fmt.Errorf("crypto: создание AES блока: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("crypto: создание GCM: %w", err)
	}

	// Генерируем случайный nonce (12 байт — стандарт GCM)
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", fmt.Errorf("crypto: генерация nonce: %w", err)
	}

	// GCM.Seal добавляет tag (16 байт) в конец ciphertext
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ciphertext),
		base64.StdEncoding.EncodeToString(nonce),
		nil
}

// DecryptText дешифрует данные, зашифрованные EncryptText.
func (c *Cipher) DecryptText(ciphertextB64, ivB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("crypto: base64 decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(ivB64)
	if err != nil {
		return nil, fmt.Errorf("crypto: base64 decode nonce: %w", err)
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("crypto: создание AES блока: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: создание GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Ошибка аутентификации — либо неверный ключ, либо данные изменены
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// ─── Потоковое шифрование медиа ──────────────────────────────────────────────

// EncryptStream читает все данные из src, шифрует и записывает в dst.
// Возвращает base64(nonce), количество записанных байт и ошибку.
//
// Примечание: для файлов >100MB рекомендуется chunked подход.
// Текущая реализация буферизует весь файл в памяти.
func (c *Cipher) EncryptStream(src io.Reader, dst io.Writer) (ivB64 string, written int64, err error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", 0, fmt.Errorf("crypto: создание AES блока: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", 0, fmt.Errorf("crypto: создание GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", 0, fmt.Errorf("crypto: генерация nonce: %w", err)
	}

	// Читаем исходный файл
	plaintext, err := io.ReadAll(src)
	if err != nil {
		return "", 0, fmt.Errorf("crypto: чтение источника: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	n, err := dst.Write(ciphertext)
	if err != nil {
		return "", 0, fmt.Errorf("crypto: запись шифротекста: %w", err)
	}

	return base64.StdEncoding.EncodeToString(nonce), int64(n), nil
}

// DecryptStream читает зашифрованный blob из src, дешифрует и пишет в dst.
// ivB64 — base64-кодированный nonce, использованный при шифровании.
func (c *Cipher) DecryptStream(src io.Reader, dst io.Writer, ivB64 string) error {
	nonce, err := base64.StdEncoding.DecodeString(ivB64)
	if err != nil {
		return fmt.Errorf("crypto: base64 decode nonce: %w", err)
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return fmt.Errorf("crypto: создание AES блока: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("crypto: создание GCM: %w", err)
	}

	ciphertext, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("crypto: чтение шифротекста: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return ErrDecryptionFailed
	}

	if _, err = dst.Write(plaintext); err != nil {
		return fmt.Errorf("crypto: запись открытого текста: %w", err)
	}

	return nil
}

// GenerateKey генерирует криптографически стойкий 32-байтовый ключ.
// Используется для генерации APP_ENCRYPTION_KEY.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("crypto: генерация ключа: %w", err)
	}
	return key, nil
}
