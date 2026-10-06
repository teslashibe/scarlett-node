package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/teslashibe/scarlett-node/internal/worker"
	x "github.com/teslashibe/x-go"
)

func TestXReconnectRechecksIdentityVerifiedDuringReplacement(t *testing.T) {
	for _, candidateID := range []string{"123", "456"} {
		t.Run(candidateID, func(t *testing.T) {
			dir := identityRegistryFixture(t)
			var output bytes.Buffer
			if err := fixtureAccountsCommand([]string{"connect", "x_read", "first", "1"}, strings.NewReader(`{"auth_token":"synthetic-first","ct0":"csrf"}`), &output); err != nil {
				t.Fatal(err)
			}
			registry, err := loadAccounts(accountFilePath(dir))
			if err != nil || len(registry.Accounts) != 1 {
				t.Fatal("fixture registration unavailable", err)
			}
			path := registry.Accounts[0].Path
			prior, err := readLocalFile(path, 65536)
			if err != nil {
				t.Fatal(err)
			}
			// Simulate an older registration before its first warm validation.
			if err := os.Remove(xIdentitiesPath(dir)); err != nil {
				t.Fatal(err)
			}
			output.Reset()
			err = accountsCommandWithVerifier([]string{"reconnect", "x_read", "first"}, strings.NewReader(`{"auth_token":"synthetic-new","ct0":"new-csrf"}`), &output, func(context.Context, x.Session) (worker.VerifiedXIdentity, error) {
				// This is the runtime observer's actual protected persistence path,
				// executed while staged verification holds neither registry lock.
				old := worker.VerifiedXIdentity{ID: "123", Username: "fixture_user", Stamp: xCredentialStamp(path)}
				if err := saveXIdentity(dir, path, old); err != nil {
					return worker.VerifiedXIdentity{}, err
				}
				return worker.VerifiedXIdentity{ID: candidateID, Username: "fixture_user"}, nil
			})
			current, readErr := readLocalFile(path, 65536)
			if readErr != nil {
				t.Fatal(readErr)
			}
			identity, readErr := verifiedXIdentity(dir, path)
			if readErr != nil || identity.ID != "123" {
				t.Fatal("concurrent verified identity lost", readErr)
			}
			if candidateID == "456" {
				if err == nil || !strings.Contains(output.String(), `"code":"identity_mismatch"`) || !bytes.Equal(prior, current) {
					t.Fatal("replacement overwrote a concurrently verified user", err)
				}
			} else if err != nil || bytes.Equal(prior, current) {
				t.Fatal("same-user reconnect was rejected", err)
			}
		})
	}
}
