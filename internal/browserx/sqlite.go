package browserx

import (
	"context"
	"database/sql"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ncruces/go-sqlite3"
	sqliteDriver "github.com/ncruces/go-sqlite3/driver"
)

func storeURI(path string) string {
	p := filepath.ToSlash(path)
	if runtime.GOOS == "windows" {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	q := url.Values{"mode": {"ro"}, "immutable": {"1"}, "_pragma": {"query_only(ON)", "trusted_schema(OFF)", "busy_timeout(0)", "mmap_size(0)"}}
	u.RawQuery = q.Encode()
	return u.String()
}

func readSQLite(ctx context.Context, browser, path string, selected selection) error {
	if err := checkJournals(path); err != nil {
		return err
	}
	db, err := sql.Open("sqlite3", storeURI(path))
	if err != nil {
		return Invalid
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return Invalid
	}
	defer conn.Close()
	if err = conn.Raw(func(raw any) error {
		c, ok := raw.(sqliteDriver.Conn)
		if !ok {
			return Invalid
		}
		c.Raw().Limit(sqlite3.LIMIT_LENGTH, 1<<20)
		c.Raw().Limit(sqlite3.LIMIT_SQL_LENGTH, 1<<16)
		return nil
	}); err != nil {
		return Invalid
	}
	table := "moz_cookies"
	if browser == "chrome" {
		table = "cookies"
	}
	var kind, schema string
	if conn.QueryRowContext(ctx, "SELECT type, sql FROM sqlite_schema WHERE name=?", table).Scan(&kind, &schema) != nil || kind != "table" || strings.HasPrefix(strings.ToUpper(strings.TrimSpace(schema)), "CREATE VIRTUAL") {
		return Invalid
	}
	if browser == "firefox" {
		return readFirefox(ctx, conn, selected)
	}
	return readChrome(ctx, conn, path, selected)
}

func readFirefox(ctx context.Context, conn *sql.Conn, selected selection) error {
	rows, err := conn.QueryContext(ctx, `SELECT host, name, substr(value,1,161), expiry, originAttributes, length(value)
FROM moz_cookies WHERE host IN ('x.com','.x.com','twitter.com','.twitter.com')
AND name IN ('auth_token','ct0') AND path='/' AND isSecure=1 LIMIT 33`)
	if err != nil {
		return Invalid
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 32 {
			return Ambiguous
		}
		var host, name, value, attributes string
		var expiry, length int64
		if rows.Scan(&host, &name, &value, &expiry, &attributes, &length) != nil || length > 160 || len(attributes) > 1024 {
			return Invalid
		}
		if expiry != 0 && expiry <= time.Now().Unix() {
			continue
		}
		if err = selected.add(domain(host)+"|"+attributes, name, value); err != nil {
			return err
		}
	}
	if rows.Err() != nil {
		return Invalid
	}
	return nil
}

func readChrome(ctx context.Context, conn *sql.Conn, path string, selected selection) error {
	var version int
	if conn.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='version'").Scan(&version) != nil || version < 1 || version > 1000 {
		return Invalid
	}
	// Chrome added partition keys without changing the cookie file name.
	partition := "''"
	columns, err := conn.QueryContext(ctx, "PRAGMA table_info(cookies)")
	if err != nil {
		return Invalid
	}
	for columns.Next() {
		var index, notnull, pk int
		var name, kind string
		var defaultValue any
		if columns.Scan(&index, &name, &kind, &notnull, &defaultValue, &pk) != nil {
			columns.Close()
			return Invalid
		}
		if name == "top_frame_site_key" {
			partition = "top_frame_site_key"
		}
	}
	if columns.Err() != nil {
		columns.Close()
		return Invalid
	}
	columns.Close()
	rows, err := conn.QueryContext(ctx, `SELECT host_key, name, substr(value,1,161), substr(encrypted_value,1,1025), expires_utc, `+partition+`, length(value), length(encrypted_value)
FROM cookies WHERE host_key IN ('x.com','.x.com','twitter.com','.twitter.com')
AND name IN ('auth_token','ct0') AND path='/' AND is_secure=1 LIMIT 33`)
	if err != nil {
		return Invalid
	}
	defer rows.Close()
	decryptor := chromeDecryptor{ctx: ctx, path: path, version: version}
	defer decryptor.clear()
	count := 0
	for rows.Next() {
		count++
		if count > 32 {
			return Ambiguous
		}
		var host, name, value, frame string
		var encrypted []byte
		var expiry, plainLength, encryptedLength int64
		if rows.Scan(&host, &name, &value, &encrypted, &expiry, &frame, &plainLength, &encryptedLength) != nil || plainLength > 160 || encryptedLength > 1024 || len(frame) > 1024 {
			return Invalid
		}
		if expiry != 0 && expiry/1000000-11644473600 <= time.Now().Unix() {
			continue
		}
		if len(encrypted) > 0 {
			decrypted, e := decryptor.value(host, encrypted)
			clear(encrypted)
			if e != nil {
				return e
			}
			value = string(decrypted)
			clear(decrypted)
		}
		if err = selected.add(domain(host)+"|"+frame, name, value); err != nil {
			return err
		}
	}
	if rows.Err() != nil {
		return Invalid
	}
	return nil
}
