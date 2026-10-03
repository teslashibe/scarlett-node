package browserx

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math"
	"time"
)

func readSafari(ctx context.Context, file io.Reader, size int64, selected selection) error {
	var header [8]byte
	if _, err := io.ReadFull(file, header[:]); err != nil || string(header[:4]) != "cook" {
		return Invalid
	}
	pages := int(binary.BigEndian.Uint32(header[4:]))
	if pages < 1 || pages > 4096 || int64(8+4*pages) > size {
		return Invalid
	}
	table := make([]byte, 4*pages)
	if _, err := io.ReadFull(file, table); err != nil {
		return Invalid
	}
	remaining := size - int64(8+len(table))
	selectedRows := 0
	for i := 0; i < pages; i++ {
		if ctx.Err() != nil {
			return Busy
		}
		length := int(binary.BigEndian.Uint32(table[i*4:]))
		if length < 12 || length > 4<<20 || int64(length) > remaining {
			return Invalid
		}
		page := make([]byte, length)
		if _, err := io.ReadFull(file, page); err != nil {
			return Invalid
		}
		remaining -= int64(length)
		if !bytes.Equal(page[:4], []byte{0, 0, 1, 0}) {
			return Invalid
		}
		count := int(binary.LittleEndian.Uint32(page[4:]))
		if count > 8192 || count > (length-12)/4 {
			return Invalid
		}
		for j := 0; j < count; j++ {
			if ctx.Err() != nil {
				return Busy
			}
			offset := int(binary.LittleEndian.Uint32(page[8+j*4:]))
			if offset < 12+4*count || offset > length-56 {
				return Invalid
			}
			n := int(binary.LittleEndian.Uint32(page[offset:]))
			if n < 56 || n > length-offset {
				return Invalid
			}
			record := page[offset : offset+n]
			host, err := safariField(record, 16, 512)
			if err != nil {
				return err
			}
			root := domain(host)
			if root == "" {
				continue
			}
			name, err := safariField(record, 20, 64)
			if err != nil {
				return err
			}
			if !cookieName(name) {
				continue
			}
			path, err := safariField(record, 24, 512)
			if err != nil {
				return err
			}
			if path != "/" || binary.LittleEndian.Uint32(record[8:])&1 == 0 {
				continue
			}
			expiry := math.Float64frombits(binary.LittleEndian.Uint64(record[40:]))
			if math.IsNaN(expiry) || math.IsInf(expiry, 0) || expiry < 0 {
				return Invalid
			}
			if expiry != 0 && expiry <= float64(time.Now().Unix()-978307200) {
				continue
			}
			selectedRows++
			if selectedRows > 32 {
				return Ambiguous
			}
			value, err := safariField(record, 28, 160)
			if err != nil {
				return err
			}
			if err = selected.add(root, name, value); err != nil {
				return err
			}
		}
		clear(page)
	}
	return nil
}

func safariField(record []byte, position, max int) (string, error) {
	if position < 0 || position > len(record)-4 {
		return "", Invalid
	}
	offset := int(binary.LittleEndian.Uint32(record[position:]))
	if offset < 56 || offset >= len(record) {
		return "", Invalid
	}
	end := len(record)
	if end-offset > max+1 {
		end = offset + max + 1
	}
	value := record[offset:end]
	n := bytes.IndexByte(value, 0)
	if n < 0 {
		return "", Invalid
	}
	return string(value[:n]), nil
}
