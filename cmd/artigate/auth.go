package main

// Low-side credentials. ARTIGATE_LOW_AUTH holds one or more argon2id-hashed
// user:password credentials; the `hashpw` subcommand generates the hashes. These
// are consumed by the session login flow in login.go, which protects the
// low-side dashboard. The high side is never authenticated.

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2 parameters for newly generated hashes. Verification reads the
// parameters out of each stored hash, so these may change without invalidating
// existing credentials.
const (
	argonMemory      = 64 * 1024 // KiB
	argonIterations  = 3
	argonParallelism = 1
	argonSaltLen     = 16
	argonKeyLen      = 32

	// Sanity bounds enforced when verifying a stored hash's embedded parameters,
	// to reject malformed values that would crash argon2.IDKey or trigger an
	// absurd allocation. Generous enough to accommodate stronger future presets.
	maxArgonMemory     = 1 << 20 // 1 GiB in KiB
	maxArgonIterations = 1 << 20
)

// parseLowAuth parses ARTIGATE_LOW_AUTH into a username->hash map. Entries are
// "username:<argon2id PHC hash>" separated by ';' or newlines (not commas, which
// occur inside an argon2 hash). An empty value means authentication is disabled.
func parseLowAuth(s string) (map[string]string, error) {
	users := map[string]string{}
	for _, entry := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == '\n' || r == '\r' }) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		i := strings.IndexByte(entry, ':')
		if i <= 0 {
			return nil, errors.New("invalid ARTIGATE_LOW_AUTH entry (want username:argon2-hash)")
		}
		user, hash := strings.TrimSpace(entry[:i]), strings.TrimSpace(entry[i+1:])
		if user == "" || hash == "" {
			return nil, errors.New("invalid ARTIGATE_LOW_AUTH entry (empty username or hash)")
		}
		if !strings.HasPrefix(hash, "$argon2id$") {
			return nil, fmt.Errorf("credential for %q is not an argon2id hash", user)
		}
		users[user] = hash
	}
	// A non-empty value that yields no credentials (e.g. ";" or whitespace from an
	// env/compose quoting slip) must not silently disable auth: fail closed so the
	// operator who tried to enable auth is not left with an open dashboard.
	if len(users) == 0 && s != "" {
		return nil, errors.New("ARTIGATE_LOW_AUTH is set but contains no valid credentials")
	}
	return users, nil
}

// authStatus describes the configured auth for a startup log line.
func authStatus(users map[string]string) string {
	if len(users) == 0 {
		return "disabled"
	}
	return fmt.Sprintf("%d user(s)", len(users))
}

// hashArgon2 produces an argon2id PHC-format hash of password with a random salt.
func hashArgon2(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// verifyArgon2 reports whether password matches the argon2id PHC hash, using the
// parameters embedded in the hash.
func verifyArgon2(password, phc string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory, iterations, parallelism int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	// The parameters and digest come straight from the stored hash, so guard
	// against malformed values before handing them to argon2.IDKey: t=0 or
	// p=0/p>255 make it panic, a huge or negative m triggers an enormous
	// allocation, and an empty digest would make the ConstantTimeCompare below
	// succeed for any password (an auth bypass).
	if iterations < 1 || iterations > maxArgonIterations ||
		parallelism < 1 || parallelism > 255 ||
		memory < 8 || memory > maxArgonMemory ||
		len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(parallelism), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// credentialOK reports whether user/pass match a configured argon2id credential.
func credentialOK(users map[string]string, user, pass string) bool {
	hash, ok := users[user]
	if !ok {
		return false
	}
	return verifyArgon2(pass, hash)
}

// runHashpw generates an argon2id hash for a password, to paste into
// ARTIGATE_LOW_AUTH. The password comes from --password or, if empty, one line
// read from stdin (so it can be piped without appearing in the process args).
func runHashpw(args []string) {
	fs := flag.NewFlagSet("hashpw", flag.ExitOnError)
	user := fs.String("user", "", "username to prefix the hash with (prints user:hash)")
	pw := fs.String("password", "", "password to hash; if empty, read one line from stdin")
	_ = fs.Parse(args)

	password := *pw
	if password == "" {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			log.Fatal("no password provided (use --password or pipe one on stdin)")
		}
		password = strings.TrimRight(line, "\r\n")
	}
	if password == "" {
		log.Fatal("empty password")
	}
	hash, err := hashArgon2(password)
	must(err)
	if *user != "" {
		fmt.Printf("%s:%s\n", *user, hash)
	} else {
		fmt.Println(hash)
	}
}
