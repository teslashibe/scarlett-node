package webruntime

import (
	"os"
	"testing"
)

func TestReadHelperPortLineEndings(t *testing.T) {
	for line, want := range map[string]int{
		helperPortPrefix + "50894\n":     50894,
		helperPortPrefix + "50894\r\n":   50894, // Python text-mode stdout on Windows
		helperPortPrefix + "50894\r\r\n": 0,
		helperPortPrefix + "050894\r\n":  0,
		"other\r\n":                      0,
	} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		ports := make(chan int, 1)
		go readHelperPort(r, ports)
		if _, err = w.WriteString(line); err != nil {
			t.Fatal(err)
		}
		w.Close()
		if got := <-ports; got != want {
			t.Errorf("%q: port %d, want %d", line, got, want)
		}
	}
}
