package main

import (
	"strings"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	hash, err := hashArgon2("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash = %q, want $argon2id$ prefix", hash)
	}
	if !verifyArgon2("correct horse battery staple", hash) {
		t.Error("correct password should verify")
	}
	if verifyArgon2("wrong password", hash) {
		t.Error("wrong password should not verify")
	}
	// Two hashes of the same password differ (random salt) yet both verify.
	hash2, err := hashArgon2("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if hash == hash2 {
		t.Error("hashes of same password should differ (random salt)")
	}
	if !verifyArgon2("correct horse battery staple", hash2) {
		t.Error("second hash should also verify")
	}
}

func TestVerifyArgon2Rejects(t *testing.T) {
	valid, err := hashArgon2("pw")
	if err != nil {
		t.Fatal(err)
	}
	bad := []string{
		"",
		"not-a-hash",
		"$argon2i$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA",  // wrong variant
		"$argon2id$v=99$m=65536,t=3,p=1$c2FsdA$aGFzaA", // wrong version
		"$argon2id$m=65536,t=3,p=1$c2FsdA$aGFzaA",      // missing version field
		"$argon2id$v=19$bad$c2FsdA$aGFzaA",             // unparseable params
		"$argon2id$v=19$m=65536,t=3,p=1$!!!$aGFzaA",    // bad salt base64
		"$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$!!!",    // bad hash base64
		valid[:len(valid)-4],                           // truncated
	}
	for _, h := range bad {
		if verifyArgon2("pw", h) {
			t.Errorf("verifyArgon2 accepted malformed hash %q", h)
		}
	}
}

func TestParseLowAuthValid(t *testing.T) {
	alice, err := hashArgon2("alice-pw")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := hashArgon2("bob-pw")
	if err != nil {
		t.Fatal(err)
	}

	// Empty value disables auth.
	if users, err := parseLowAuth(""); err != nil || len(users) != 0 {
		t.Fatalf("empty: users = %v, err = %v", users, err)
	}

	// Several users, separated by a mix of ';' and newlines with stray spaces.
	// The argon2 params (m=..,t=..,p=..) contain commas, so the hashes must
	// survive intact — that's why the separator is not a comma.
	env := "alice:" + alice + " ; \n bob:" + bob + "\n"
	users, err := parseLowAuth(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("want 2 users, got %v", users)
	}
	if users["alice"] != alice {
		t.Errorf("alice hash mangled: %q", users["alice"])
	}
	if users["bob"] != bob {
		t.Errorf("bob hash mangled: %q", users["bob"])
	}
}

func TestParseLowAuthRejects(t *testing.T) {
	alice, err := hashArgon2("alice-pw")
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"missing colon":     "aliceonly",
		"non-argon2 hash":   "alice:plaintext",
		"empty username":    ":" + alice,
		"empty hash":        "alice:",
		"wrong hash scheme": "alice:$2y$10$abcdefg",
	}
	for name, env := range bad {
		if _, err := parseLowAuth(env); err == nil {
			t.Errorf("%s: parseLowAuth(%q) should error", name, env)
		}
	}
}
