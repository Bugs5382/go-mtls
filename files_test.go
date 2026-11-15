package mtls_test

/*
MIT License

Copyright (c) 2026 Shane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bugs5382/go-mtls"
)

func TestFilesFromEnvReadsTheThreeNames(t *testing.T) {
	t.Setenv(mtls.EnvCertFile, "/tls/tls.crt")
	t.Setenv(mtls.EnvKeyFile, "/tls/tls.key")
	t.Setenv(mtls.EnvCAFile, "/tls/ca.crt")
	got, err := mtls.FilesFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if want := (mtls.Files{Cert: "/tls/tls.crt", Key: "/tls/tls.key", CA: "/tls/ca.crt"}); got != want {
		t.Fatalf("FilesFromEnv() = %+v, want %+v", got, want)
	}
	if mtls.EnvCertFile != "MTLS_CERT_FILE" || mtls.EnvKeyFile != "MTLS_KEY_FILE" || mtls.EnvCAFile != "MTLS_CA_FILE" {
		t.Fatal("the environment variable names are part of the contract")
	}
}

func TestFilesFromEnvNamesEveryMissingVariable(t *testing.T) {
	t.Setenv(mtls.EnvCertFile, "/tls/tls.crt")
	t.Setenv(mtls.EnvKeyFile, "")
	t.Setenv(mtls.EnvCAFile, "")
	_, err := mtls.FilesFromEnv()
	if !errors.Is(err, mtls.ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	for _, name := range []string{mtls.EnvKeyFile, mtls.EnvCAFile} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name %s", err, name)
		}
	}
	if strings.Contains(err.Error(), mtls.EnvCertFile) {
		t.Errorf("error %q names a variable that is set", err)
	}
}

func TestANewProviderNamesAMissingFile(t *testing.T) {
	ca := newCA(t)
	id := newIdentity(t, ca, leaf{names: []string{"localhost"}})
	for role, path := range map[string]string{"certificate": id.files.Cert, "key": id.files.Key, "CA": id.files.CA} {
		t.Run(role, func(t *testing.T) {
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.WriteFile(path, saved, 0o600) }()
			_, err = mtls.NewProvider(id.files)
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("err = %v, want it to wrap fs.ErrNotExist", err)
			}
			var fe *mtls.FileError
			if !errors.As(err, &fe) || fe.Path != path || fe.Role != role {
				t.Fatalf("err = %v, want a FileError for the %s at %s", err, role, path)
			}
			if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), role) {
				t.Errorf("error %q should name the role and the path", err)
			}
		})
	}
}

func TestANewProviderRefusesFilesThatAreNotPEM(t *testing.T) {
	ca := newCA(t)
	id := newIdentity(t, ca, leaf{names: []string{"localhost"}})
	replace(t, id.files.CA, []byte("not a certificate"))
	if _, err := mtls.NewProvider(id.files); err == nil || !strings.Contains(err.Error(), id.files.CA) {
		t.Fatalf("err = %v, want one naming %s", err, id.files.CA)
	}
	id.writeCA(t, ca.pem)
	replace(t, id.files.Key, []byte("not a key"))
	if _, err := mtls.NewProvider(id.files); err == nil || !strings.Contains(err.Error(), filepath.Base(id.files.Key)) {
		t.Fatalf("err = %v, want one naming the key file", err)
	}
}

func TestANewProviderRefusesAnEmptyPath(t *testing.T) {
	if _, err := mtls.NewProvider(mtls.Files{}); !errors.Is(err, mtls.ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}
