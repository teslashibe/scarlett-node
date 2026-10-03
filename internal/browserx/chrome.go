package browserx

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"runtime"
)

type chromeDecryptor struct {
	ctx     context.Context
	path    string
	version int
	key     []byte
}

func (c *chromeDecryptor) clear() { clear(c.key); c.key = nil }
func (c *chromeDecryptor) value(host string, encrypted []byte) ([]byte, error) {
	if !bytes.HasPrefix(encrypted, []byte("v10")) {
		return nil, Protected
	}
	if c.key == nil {
		var err error
		c.key, err = nativeChromeKey(c.ctx, c.path)
		if err != nil {
			return nil, Protected
		}
	}
	mode := "cbc"
	if runtime.GOOS == "windows" {
		mode = "gcm"
	}
	return decryptChrome(mode, c.key, host, c.version, encrypted)
}

func decryptChrome(mode string, key []byte, host string, version int, encrypted []byte) ([]byte, error) {
	if len(encrypted) < 4 || !bytes.HasPrefix(encrypted, []byte("v10")) {
		return nil, Protected
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, Protected
	}
	body := encrypted[3:]
	var plain []byte
	switch mode {
	case "cbc":
		if len(body) == 0 || len(body)%aes.BlockSize != 0 {
			return nil, Invalid
		}
		plain = make([]byte, len(body))
		cipher.NewCBCDecrypter(block, []byte("                ")).CryptBlocks(plain, body)
		padding := int(plain[len(plain)-1])
		if padding < 1 || padding > aes.BlockSize || padding > len(plain) {
			clear(plain)
			return nil, Protected
		}
		for _, b := range plain[len(plain)-padding:] {
			if int(b) != padding {
				clear(plain)
				return nil, Protected
			}
		}
		plain = plain[:len(plain)-padding]
	case "gcm":
		gcm, e := cipher.NewGCM(block)
		if e != nil || len(body) < gcm.NonceSize()+gcm.Overhead() {
			return nil, Invalid
		}
		plain, err = gcm.Open(nil, body[:gcm.NonceSize()], body[gcm.NonceSize():], nil)
		if err != nil {
			return nil, Protected
		}
	default:
		return nil, Unsupported
	}
	if version >= 24 {
		digest := sha256.Sum256([]byte(host))
		if len(plain) < sha256.Size || !bytes.Equal(plain[:sha256.Size], digest[:]) {
			clear(plain)
			return nil, Protected
		}
		out := bytes.Clone(plain[sha256.Size:])
		clear(plain)
		return out, nil
	}
	return plain, nil
}
