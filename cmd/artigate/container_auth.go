package main

import (
	"errors"
	"net/url"
	"strings"
)

// containerAuthChallenge keeps comma-delimited parameters together without
// treating commas inside quoted values as challenge or parameter separators.
type containerAuthChallenge struct {
	scheme string
	fields []string
}

func parseContainerAuthChallenges(header string) ([]containerAuthChallenge, error) {
	fields, err := splitContainerAuthFields(header)
	if err != nil {
		return nil, err
	}
	var challenges []containerAuthChallenge
	for _, field := range fields {
		field = strings.Trim(field, " \t")
		if field == "" {
			continue
		}
		token, rest := cutContainerAuthToken(field)
		if token == "" {
			return nil, errors.New("invalid registry authentication challenge")
		}
		if strings.HasPrefix(strings.TrimLeft(rest, " \t"), "=") {
			if len(challenges) == 0 {
				return nil, errors.New("registry authentication parameter has no challenge")
			}
			last := &challenges[len(challenges)-1]
			last.fields = append(last.fields, field)
			continue
		}
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			return nil, errors.New("invalid registry authentication scheme")
		}
		challenges = append(challenges, containerAuthChallenge{scheme: token, fields: []string{strings.Trim(rest, " \t")}})
	}
	return challenges, nil
}

func splitContainerAuthFields(header string) ([]string, error) {
	var fields []string
	start := 0
	quoted, escaped := false, false
	for i := range len(header) {
		ch := header[i]
		if (ch < ' ' && ch != '\t') || ch == 0x7f {
			return nil, errors.New("invalid character in registry authentication challenge")
		}
		if escaped {
			escaped = false
			continue
		}
		switch ch {
		case '\\':
			escaped = quoted
		case '"':
			quoted = !quoted
		case ',':
			if !quoted {
				fields = append(fields, header[start:i])
				start = i + 1
			}
		}
	}
	if quoted {
		return nil, errors.New("unterminated registry authentication parameter")
	}
	return append(fields, header[start:]), nil
}

func cutContainerAuthToken(s string) (token, rest string) {
	i := 0
	for i < len(s) && isContainerAuthTokenByte(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

func isContainerAuthTokenByte(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
		strings.ContainsRune("!#$%&'*+-.^_`|~", rune(ch))
}

func (c containerAuthChallenge) parameters() (map[string]string, error) {
	params := make(map[string]string, len(c.fields))
	for _, field := range c.fields {
		if field == "" {
			continue
		}
		key, rest := cutContainerAuthToken(field)
		rest = strings.TrimLeft(rest, " \t")
		if key == "" || !strings.HasPrefix(rest, "=") {
			return nil, errors.New("invalid registry authentication parameter")
		}
		key = strings.ToLower(key)
		if _, exists := params[key]; exists {
			return nil, errors.New("duplicate registry authentication parameter")
		}
		value, err := decodeContainerAuthValue(strings.Trim(rest[1:], " \t"))
		if err != nil {
			return nil, err
		}
		params[key] = value
	}
	return params, nil
}

func decodeContainerAuthValue(value string) (string, error) {
	if !strings.HasPrefix(value, `"`) {
		token, rest := cutContainerAuthToken(value)
		if token == "" || rest != "" {
			return "", errors.New("invalid registry authentication value")
		}
		return token, nil
	}
	var decoded strings.Builder
	for i := 1; i < len(value); i++ {
		ch := value[i]
		if ch == '"' {
			if i != len(value)-1 {
				return "", errors.New("invalid text after registry authentication value")
			}
			return decoded.String(), nil
		}
		if ch == '\\' {
			i++
			if i == len(value) {
				break
			}
			ch = value[i]
		}
		decoded.WriteByte(ch)
	}
	return "", errors.New("unterminated registry authentication value")
}

// parseBearerChallenge accepts a challenge list and extracts the first Bearer
// challenge. HTTP quoted pairs differ from Go string escapes (e.g. \, is valid).
func parseBearerChallenge(header string) (realm string, params map[string]string, err error) {
	challenges, err := parseContainerAuthChallenges(header)
	if err != nil {
		return "", nil, err
	}
	for _, challenge := range challenges {
		if !strings.EqualFold(challenge.scheme, "Bearer") {
			continue
		}
		params, err = challenge.parameters()
		if err != nil {
			return "", nil, err
		}
		realm = params["realm"]
		if err := validateContainerTokenRealm(realm); err != nil {
			return "", nil, err
		}
		return realm, params, nil
	}
	return "", nil, errors.New("registry response has no Bearer challenge")
}

func validateContainerTokenRealm(realm string) error {
	if realm == "" {
		return errors.New("Bearer challenge has no realm")
	}
	u, err := url.Parse(realm)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid Bearer realm: expected an absolute HTTP(S) URL without userinfo or fragment")
	}
	if _, err := url.ParseQuery(u.RawQuery); err != nil {
		return errors.New("invalid Bearer realm query")
	}
	return nil
}

// containerAuthError keeps URL-bearing transport/parse errors out of user
// messages while preserving their causes for errors.Is/As and cancellation.
type containerAuthError struct {
	message string
	cause   error
}

func (e *containerAuthError) Error() string { return e.message }
func (e *containerAuthError) Unwrap() error { return e.cause }
