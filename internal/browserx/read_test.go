package browserx

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type cookieFixture struct {
	host, name, value, attributes, path string
	expiry                              int64
	secure                              bool
	encrypted                           []byte
}

const fakeToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const fakeCSRF = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func fixtureStore(t *testing.T, browser string, entries []cookieFixture) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := "cookies.sqlite"
	if browser == "chrome" {
		name = "Cookies"
	}
	path := filepath.Join(dir, name)
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal("isolated fixture database unavailable")
	}
	defer db.Close()
	create := `CREATE TABLE moz_cookies(host TEXT,name TEXT,value TEXT,expiry INTEGER,originAttributes TEXT,path TEXT,isSecure INTEGER)`
	insert := `INSERT INTO moz_cookies VALUES(?,?,?,?,?,?,?)`
	if browser == "chrome" {
		create = `CREATE TABLE cookies(host_key TEXT,name TEXT,value TEXT,expires_utc INTEGER,top_frame_site_key TEXT,path TEXT,is_secure INTEGER,encrypted_value BLOB);CREATE TABLE meta(key TEXT,value TEXT);INSERT INTO meta VALUES('version','24')`
		insert = `INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?)`
	}
	if _, err = db.Exec(create); err != nil {
		t.Fatal("fixture schema unavailable", err)
	}
	for _, c := range entries {
		args := []any{c.host, c.name, c.value, c.expiry, c.attributes, c.path, c.secure}
		if browser == "chrome" {
			args = append(args, c.encrypted)
		}
		if _, err = db.Exec(insert, args...); err != nil {
			t.Fatal("synthetic fixture insert failed", err)
		}
	}
	return path
}

func pairFixtures(host, attributes string) []cookieFixture {
	return []cookieFixture{{host: host, name: "auth_token", value: fakeToken, attributes: attributes, path: "/", secure: true}, {host: host, name: "ct0", value: fakeCSRF, attributes: attributes, path: "/", secure: true}}
}

func TestFirefoxImportSelectsOnlyCompleteUnexpiredXRootSession(t *testing.T) {
	entries := pairFixtures(".x.com", "")
	entries = append(entries, cookieFixture{host: "x.com.evil.invalid", name: "auth_token", value: "unrelated-cookie-must-never-be-imported", path: "/", secure: true}, cookieFixture{host: ".x.com", name: "other", value: "unrelated-name", path: "/", secure: true})
	path := fixtureStore(t, "firefox", entries)
	before, _ := os.ReadFile(path)
	raw, err := ReadSession(context.Background(), "firefox", path)
	if err != nil {
		t.Fatal("isolated import failed", err)
	}
	var imported map[string]string
	if json.Unmarshal(raw, &imported) != nil || len(imported) != 2 || imported["auth_token"] != fakeToken || imported["ct0"] != fakeCSRF {
		t.Fatal("import returned incorrect selected fields")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("browser database was modified")
	}
	for _, suffix := range []string{"-wal", "-journal", "-shm"} {
		if _, err = os.Lstat(path + suffix); !os.IsNotExist(err) {
			t.Fatal("browser auxiliary file created", suffix)
		}
	}
}

func TestFirefoxImportRefusesMixedAmbiguousExpiredAndWrongScopeCookies(t *testing.T) {
	for name, entries := range map[string][]cookieFixture{
		"cross-domain":    {{host: ".x.com", name: "auth_token", value: fakeToken, path: "/", secure: true}, {host: ".twitter.com", name: "ct0", value: fakeCSRF, path: "/", secure: true}},
		"expired":         {{host: ".x.com", name: "auth_token", value: fakeToken, path: "/", secure: true, expiry: time.Now().Unix() - 1}, {host: ".x.com", name: "ct0", value: fakeCSRF, path: "/", secure: true}},
		"wrong-path":      {{host: ".x.com", name: "auth_token", value: fakeToken, path: "/", secure: true}, {host: ".x.com", name: "ct0", value: fakeCSRF, path: "/api", secure: true}},
		"insecure":        {{host: ".x.com", name: "auth_token", value: fakeToken, path: "/", secure: true}, {host: ".x.com", name: "ct0", value: fakeCSRF, path: "/", secure: false}},
		"cross-container": {{host: ".x.com", name: "auth_token", value: fakeToken, attributes: "userContextId=1", path: "/", secure: true}, {host: ".x.com", name: "ct0", value: fakeCSRF, attributes: "userContextId=2", path: "/", secure: true}},
	} {
		t.Run(name, func(t *testing.T) {
			path := fixtureStore(t, "firefox", entries)
			raw, err := ReadSession(context.Background(), "firefox", path)
			if err != Missing || raw != nil {
				t.Fatal("invalid source produced a session", err)
			}
		})
	}
	entries := pairFixtures(".x.com", "")
	other := pairFixtures(".x.com", "userContextId=1")
	other[0].value = strings.Repeat("c", 40)
	entries = append(entries, other...)
	if raw, err := ReadSession(context.Background(), "firefox", fixtureStore(t, "firefox", entries)); err != Ambiguous || raw != nil {
		t.Fatal("multiple identities were silently selected", err)
	}
}

func TestImportRefusesLiveJournalSymlinkAndCancelledContext(t *testing.T) {
	path := fixtureStore(t, "firefox", pairFixtures(".x.com", ""))
	if err := os.WriteFile(path+"-wal", []byte("synthetic active WAL"), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := ReadSession(context.Background(), "firefox", path); err != Busy || raw != nil {
		t.Fatal("live journal was ignored", err)
	}
	os.Remove(path + "-wal")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if raw, err := ReadSession(ctx, "firefox", path); err == nil || raw != nil {
		t.Fatal("cancelled import returned credentials")
	}
	if runtime.GOOS != "windows" {
		dir, _ := filepath.EvalSymlinks(t.TempDir())
		link := filepath.Join(dir, "cookies.sqlite")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if raw, err := ReadSession(context.Background(), "firefox", link); err != Protected || raw != nil {
			t.Fatal("symlinked cookie store was accepted", err)
		}
	}
}

func TestChromePlaintextAndProtectedCookieScope(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("Chrome platform imports are Mac/Windows only")
	}
	entries := pairFixtures(".x.com", "")
	entries = append(entries, cookieFixture{host: "other.invalid", name: "auth_token", path: "/", secure: true, encrypted: []byte("v20unrelated")})
	if _, err := ReadSession(context.Background(), "chrome", fixtureStore(t, "chrome", entries)); err != nil {
		t.Fatal("unrelated protected cookie affected import", err)
	}
	entries[0].encrypted = []byte("v20selected-protected-cookie")
	if raw, err := ReadSession(context.Background(), "chrome", fixtureStore(t, "chrome", entries)); err != Protected || raw != nil {
		t.Fatal("protected encryption did not fail closed", err)
	}
}

func TestChromeAuthenticatedDomainAndCipherBounds(t *testing.T) {
	for _, mode := range []string{"cbc", "gcm"} {
		t.Run(mode, func(t *testing.T) {
			key := bytes.Repeat([]byte{7}, 16)
			if mode == "gcm" {
				key = bytes.Repeat([]byte{7}, 32)
			}
			hash := sha256.Sum256([]byte(".x.com"))
			plain := append(bytes.Clone(hash[:]), []byte(fakeToken)...)
			block, _ := aes.NewCipher(key)
			encrypted := []byte("v10")
			if mode == "cbc" {
				padding := aes.BlockSize - len(plain)%aes.BlockSize
				plain = append(plain, bytes.Repeat([]byte{byte(padding)}, padding)...)
				ciphertext := make([]byte, len(plain))
				cipher.NewCBCEncrypter(block, []byte("                ")).CryptBlocks(ciphertext, plain)
				encrypted = append(encrypted, ciphertext...)
			} else {
				gcm, _ := cipher.NewGCM(block)
				nonce := make([]byte, gcm.NonceSize())
				encrypted = append(encrypted, nonce...)
				encrypted = append(encrypted, gcm.Seal(nil, nonce, plain, nil)...)
			}
			decoded, err := decryptChrome(mode, key, ".x.com", 24, encrypted)
			if err != nil || string(decoded) != fakeToken {
				t.Fatal("synthetic cipher did not decrypt correctly", err)
			}
			if raw, err := decryptChrome(mode, key, ".twitter.com", 24, encrypted); err != Protected || raw != nil {
				t.Fatal("host digest was ignored", err)
			}
			for _, bad := range [][]byte{[]byte("v10"), []byte("v20protected"), []byte("v10short")} {
				if raw, err := decryptChrome(mode, key, ".x.com", 24, bad); err == nil || raw != nil {
					t.Fatal("malformed ciphertext accepted")
				}
			}
		})
	}
}

func safariFixture(entries []cookieFixture) []byte {
	page := make([]byte, 12+4*len(entries))
	copy(page, []byte{0, 0, 1, 0})
	binary.LittleEndian.PutUint32(page[4:], uint32(len(entries)))
	for i, c := range entries {
		binary.LittleEndian.PutUint32(page[8+i*4:], uint32(len(page)))
		record := make([]byte, 56)
		if c.secure {
			binary.LittleEndian.PutUint32(record[8:], 1)
		}
		expiry := float64(0)
		if c.expiry != 0 {
			expiry = float64(c.expiry - 978307200)
		}
		binary.LittleEndian.PutUint64(record[40:], math.Float64bits(expiry))
		for j, s := range []string{c.host, c.name, c.path, c.value} {
			binary.LittleEndian.PutUint32(record[16+j*4:], uint32(len(record)))
			record = append(record, []byte(s)...)
			record = append(record, 0)
		}
		binary.LittleEndian.PutUint32(record, uint32(len(record)))
		page = append(page, record...)
	}
	file := make([]byte, 12)
	copy(file, []byte("cook"))
	binary.BigEndian.PutUint32(file[4:], 1)
	binary.BigEndian.PutUint32(file[8:], uint32(len(page)))
	return append(append(file, page...), make([]byte, 8)...)
}

func TestSafariSelectedCookiesAndBoundedMalformedRecords(t *testing.T) {
	fixture := safariFixture(append(pairFixtures(".x.com", ""), cookieFixture{host: "unrelated.invalid", name: "auth_token", value: "ignored", path: "/", secure: true}))
	selected := selection{}
	if err := readSafari(context.Background(), bytes.NewReader(fixture), int64(len(fixture)), selected); err != nil {
		t.Fatal("synthetic Safari reader failed", err)
	}
	if _, err := selected.encode(); err != nil {
		t.Fatal("Safari session missing", err)
	}
	for _, bad := range [][]byte{fixture[:7], append([]byte("cook"), []byte{255, 255, 255, 255}...), fixture[:len(fixture)/2]} {
		if err := readSafari(context.Background(), bytes.NewReader(bad), int64(len(bad)), selection{}); err == nil {
			t.Fatal("malformed Safari store accepted")
		}
	}
}

func TestProfileMetadataDoesNotReadOrExposeCookiePaths(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	profile := filepath.Join(root, "Default", "Network")
	if err := os.MkdirAll(profile, 0700); err != nil {
		t.Fatal(err)
	}
	// Deliberately unreadable/invalid contents: discovery must not read cookies.
	path := filepath.Join(profile, "Cookies")
	if err := os.WriteFile(path, []byte("invalid synthetic cookie database"), 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0600)
	profiles := discover(map[string]string{"chrome": root})
	if len(profiles) != 1 || profiles[0].Browser != "chrome" || profiles[0].Label != "Chrome / Default" {
		t.Fatal("profile metadata discovery failed")
	}
	raw, _ := json.Marshal(profiles)
	if bytes.Contains(raw, []byte(root)) || bytes.Contains(raw, []byte("invalid synthetic")) || len(profiles[0].ID) > 64 {
		t.Fatal("metadata exposed a path or credential contents")
	}
}

func FuzzSafariBounds(f *testing.F) {
	f.Add(safariFixture(pairFixtures(".x.com", "")))
	f.Add([]byte("cook\xff\xff\xff\xff"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_ = readSafari(context.Background(), bytes.NewReader(data), int64(len(data)), selection{})
	})
}
