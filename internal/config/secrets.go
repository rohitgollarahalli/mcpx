package config

import (
	"fmt"
	"os"
	"strings"
)

// Secret references let credentials live outside the config file. A value may
// embed any number of references:
//
//	${env:NAME}   the value of environment variable NAME
//	${file:PATH}  the contents of PATH, trailing newlines trimmed
//	              (Docker/Kubernetes secret mounts end with one)
//
// "$${" escapes a literal "${". References are resolved on every Load, so a
// SIGHUP after rotating a secret file picks up the new value. Resolution
// fails closed: an unset variable, unreadable file, or empty result is a load
// error, never a silently empty credential. Error messages name the reference,
// never the resolved value.
//
// Only credential-bearing fields expand: servers[].headers, servers[].env,
// auth.token, auth.clients[].token, and tracing.headers. Backend URLs do not:
// they appear in logs, errors, and the /servers endpoint.

// resolveSecrets expands secret references in every field that supports them.
func (c *Config) resolveSecrets() error {
	for i := range c.Servers {
		srv := &c.Servers[i]
		where := fmt.Sprintf("server %q", srv.Name)
		if err := expandMap(srv.Headers, where+": headers"); err != nil {
			return err
		}
		if err := expandMap(srv.Env, where+": env"); err != nil {
			return err
		}
	}
	if c.Auth != nil {
		var err error
		if c.Auth.Token, err = expandSecrets(c.Auth.Token, "auth.token"); err != nil {
			return err
		}
		for i := range c.Auth.Clients {
			where := fmt.Sprintf("auth.clients[%d].token", i)
			if c.Auth.Clients[i].Token, err = expandSecrets(c.Auth.Clients[i].Token, where); err != nil {
				return err
			}
		}
	}
	if c.Tracing != nil {
		if err := expandMap(c.Tracing.Headers, "tracing.headers"); err != nil {
			return err
		}
	}
	return nil
}

func expandMap(m map[string]string, where string) error {
	for k, v := range m {
		ev, err := expandSecrets(v, where+"."+k)
		if err != nil {
			return err
		}
		m[k] = ev
	}
	return nil
}

// expandSecrets replaces every ${provider:arg} reference in s.
func expandSecrets(s, where string) (string, error) {
	if !strings.Contains(s, "${") {
		return s, nil
	}
	var b strings.Builder
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			b.WriteString(s)
			return b.String(), nil
		}
		if i > 0 && s[i-1] == '$' { // "$${" is an escaped literal "${"
			b.WriteString(s[:i-1])
			b.WriteString("${")
			s = s[i+2:]
			continue
		}
		b.WriteString(s[:i])
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return "", fmt.Errorf("%s: unterminated secret reference (missing \"}\"; write \"$${\" for a literal \"${\")", where)
		}
		v, err := resolveRef(s[i+2:i+end], where)
		if err != nil {
			return "", err
		}
		b.WriteString(v)
		s = s[i+end+1:]
	}
}

func resolveRef(ref, where string) (string, error) {
	provider, arg, _ := strings.Cut(ref, ":")
	if arg == "" {
		return "", fmt.Errorf("%s: invalid secret reference ${%s} (use ${env:NAME} or ${file:PATH})", where, ref)
	}
	var v string
	switch provider {
	case "env":
		val, ok := os.LookupEnv(arg)
		if !ok {
			return "", fmt.Errorf("%s: environment variable %q is not set", where, arg)
		}
		v = val
	case "file":
		data, err := os.ReadFile(arg)
		if err != nil {
			return "", fmt.Errorf("%s: reading secret file: %w", where, err)
		}
		v = strings.TrimRight(string(data), "\r\n")
	default:
		return "", fmt.Errorf("%s: unknown secret provider %q in ${%s} (use env or file)", where, provider, ref)
	}
	if v == "" {
		return "", fmt.Errorf("%s: secret ${%s} resolved to an empty value", where, ref)
	}
	return v, nil
}
