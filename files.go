package mtls

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
	"fmt"
	"os"
	"strings"
)

// The environment variables that name the three files, for [FilesFromEnv].
const (
	EnvCertFile = "MTLS_CERT_FILE"
	EnvKeyFile  = "MTLS_KEY_FILE"
	EnvCAFile   = "MTLS_CA_FILE"
)

// ErrNotConfigured is returned when a file path, or the environment variable that names it, is not set.
var ErrNotConfigured = errors.New("mtls: not configured")

// Files names the three PEM files a service uses: its certificate (with any chain after it), the matching key,
// and the CA that signs every service in the cluster.
type Files struct {
	Cert, Key, CA string
}

// FilesFromEnv reads the three paths from [EnvCertFile], [EnvKeyFile] and [EnvCAFile]. When any is empty the
// error wraps [ErrNotConfigured] and names every variable that is missing.
func FilesFromEnv() (Files, error) {
	f := Files{Cert: os.Getenv(EnvCertFile), Key: os.Getenv(EnvKeyFile), CA: os.Getenv(EnvCAFile)}
	var missing []string
	for _, v := range []struct{ name, value string }{{EnvCertFile, f.Cert}, {EnvKeyFile, f.Key}, {EnvCAFile, f.CA}} {
		if v.value == "" {
			missing = append(missing, v.name)
		}
	}
	if len(missing) > 0 {
		return Files{}, fmt.Errorf("%w: set %s", ErrNotConfigured, strings.Join(missing, ", "))
	}
	return f, nil
}

// FileError says which of the three files could not be read and where it was.
type FileError struct {
	// Role is "certificate", "key" or "CA".
	Role string
	Path string
	Err  error
}

func (e *FileError) Error() string { return fmt.Sprintf("mtls: %s file %q: %v", e.Role, e.Path, e.Err) }

// Unwrap returns the underlying error, so errors.Is(err, fs.ErrNotExist) works.
func (e *FileError) Unwrap() error { return e.Err }
