//go:build li

package li

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testIdentityProfile() CorrelationIdentityProfile {
	return CorrelationIdentityProfile{Name: "example", Namespace: "tenant-a", SIPHosts: []string{"ingress.example", "egress.example"}, PhoneContexts: []string{"local.example", "+1-202"}, GlobalTEL: true, AllowNumericSIP: true, AllowBareGlobal: true, InternationalPrefixes: []string{"00"}}
}
func TestCorrelationIdentityProfilesEquivalentGlobalForms(t *testing.T) {
	profiles, err := compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{testIdentityProfile()})
	require.NoError(t, err)
	forms := []string{`"Example" <sip:+1(202)555-0100@INGRESS.EXAMPLE>;tag=first`, `<sips:0012025550100@egress.example>`, `<sip:12025550100@ingress.example;user=phone>`, `<sip:%31%32%30%32%35%35%35%30%31%30%30@ingress.example>`, `<tel:+1-202-555-0100>`}
	key := correlationIdentityWithProfiles(forms[0], profiles)
	require.NotEmpty(t, key)
	for _, form := range forms {
		require.Equal(t, key, correlationIdentityWithProfiles(form, profiles), form)
	}
	for _, form := range []string{`<sip:+442025550100@ingress.example>`, `<sip:+12025550100@other.example>`, `<tel:+12025550100;ext=123>`, `<tel:+12025550100;isub=123>`, `<sip:Alice12025550100@ingress.example>`} {
		require.NotEqual(t, key, correlationIdentityWithProfiles(form, profiles), form)
	}
}
func TestCorrelationIdentityProfilesPreserveDefaultComparison(t *testing.T) {
	for _, value := range []string{`"Name" <sip:Alice@EXAMPLE.test>;tag=1`, `<sip:+12025550100@example.test;user=phone>`, `tel:+1-202-555-0100`, `<sips:USER@example.test>`} {
		require.Equal(t, correlationIdentity(value), correlationIdentityWithProfiles(value, nil))
	}
}
func TestCorrelationIdentityProfilesLocalAndUserSemantics(t *testing.T) {
	p := testIdentityProfile()
	p.AllowBareGlobal = false
	p.InternationalPrefixes = nil
	p.AllowNumericSIP = false
	profiles, err := compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{p})
	require.NoError(t, err)
	pairs := [][2]string{
		{`<sip:1234@ingress.example>`, `<sip:1234@egress.example>`},
		{`<sip:1234@ingress.example;user=phone>`, `<sip:1234@egress.example;user=phone>`},
		{`<tel:1234;phone-context=local.example>`, `<tel:1234;phone-context=another.example>`},
		{`<tel:1234;phone-context=local.example;ext=1>`, `<tel:1234;phone-context=local.example;ext=2>`},
		{`<sip:Alice@ingress.example>`, `<sip:alice@ingress.example>`},
		{`<sip:+12025550100@ingress.example;isub=Ab;user=phone>`, `<sip:+12025550100@ingress.example;isub=ab;user=phone>`},
		{`<tel:+12025550100;foo=one>`, `<tel:+12025550100;foo=two>`},
	}
	for _, pair := range pairs {
		a := correlationIdentityWithProfiles(pair[0], profiles)
		b := correlationIdentityWithProfiles(pair[1], profiles)
		require.NotEmpty(t, a)
		require.NotEmpty(t, b)
		require.NotEqual(t, a, b, pair)
	}
	require.Equal(t, correlationIdentityWithProfiles(`<tel:12-34;phone-context=LOCAL.EXAMPLE;ext=1-2>`, profiles), correlationIdentityWithProfiles(`<tel:1234;ext=12;phone-context=local.example>`, profiles))
	require.Equal(t, correlationIdentityWithProfiles(`<sip:1234;phone-context=local.example@ingress.example;user=phone>`, profiles), correlationIdentityWithProfiles(`<tel:1234;phone-context=local.example>`, profiles))
}
func TestCorrelationIdentityProfilesNamespacesAndAmbiguity(t *testing.T) {
	p := testIdentityProfile()
	other := p
	other.Name = "other"
	other.Namespace = "tenant-b"
	other.SIPHosts = []string{"tenant-b.example"}
	other.GlobalTEL = false
	profiles, err := compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{p, other})
	require.NoError(t, err)
	require.NotEqual(t, correlationIdentityWithProfiles(`<sip:+12025550100@ingress.example>`, profiles), correlationIdentityWithProfiles(`<sip:+12025550100@tenant-b.example>`, profiles))
	other.SIPHosts = p.SIPHosts
	profiles, err = compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{p, other})
	require.NoError(t, err)
	require.Empty(t, correlationIdentityWithProfiles(`<sip:+12025550100@ingress.example>`, profiles))
}
func TestCorrelationIdentityProfilesRewriteContract(t *testing.T) {
	for _, test := range []struct {
		name   string
		rules  []CorrelationIdentityRewrite
		input  string
		usable bool
	}{
		{"route", []CorrelationIdentityRewrite{{`^99([0-9]+)$`, `${1}`}}, "9912025550100", true},
		{"conflict", []CorrelationIdentityRewrite{{`^99([0-9]+)$`, `${1}`}, {`^99([0-9]+)$`, `44${1}`}}, "9912025550100", false},
		{"cascade", []CorrelationIdentityRewrite{{`^99([0-9]+)$`, `${1}`}, {`^\+99([0-9]+)$`, `+${1}`}}, "999912025550100", false},
		{"empty", []CorrelationIdentityRewrite{{`^99([0-9]*)$`, `${1}`}}, "99", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := testIdentityProfile()
			p.RewriteRules = test.rules
			profiles, err := compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{p})
			require.NoError(t, err)
			key := correlationIdentityWithProfiles(`<sip:`+test.input+`@ingress.example>`, profiles)
			if test.usable {
				require.Equal(t, correlationIdentityWithProfiles(`<tel:+12025550100>`, profiles), key)
			} else {
				require.Empty(t, key)
			}
		})
	}
}
func TestCorrelationIdentityProfilesRejectMalformedInputs(t *testing.T) {
	profiles, err := compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{testIdentityProfile()})
	require.NoError(t, err)
	for _, value := range []string{`<sip:+12025550100@ingress.example`, "<tel:+12025550100>\r\nInjected:yes", `<tel:+12025550100;ext=1;ext=2>`, `<tel:+12025550100;ext=1;isub=2>`, `<sip:+12025550100@ingress.example?foo=bar>`, `<sip:%XX12025550100@ingress.example>`} {
		require.Empty(t, correlationIdentityWithProfiles(value, profiles), value)
	}
}

func TestCorrelationIdentityProfilesContextAndExactUserContract(t *testing.T) {
	profiles, err := compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{testIdentityProfile()})
	require.NoError(t, err)
	local := correlationIdentityWithProfiles(`<tel:12-34;phone-context=local.example>`, profiles)
	require.NotEmpty(t, local)
	require.Equal(t, local, correlationIdentityWithProfiles(`<sip:1234;phone-context=LOCAL.EXAMPLE@ingress.example;user=phone>`, profiles), "an explicit local context takes precedence over bare-global interpretation")
	require.NotEqual(t, local, correlationIdentityWithProfiles(`<tel:+1234>`, profiles))
	require.Equal(t, correlationIdentityWithProfiles(`<tel:+12025550100;isub=Ab>`, profiles), correlationIdentityWithProfiles(`<tel:+12025550100;isub=ab>`, profiles), "tel parameter comparisons are case-insensitive")
	require.Equal(t, correlationIdentityWithProfiles(`sip:+12025550100@ingress.example;tag=first`, profiles), correlationIdentityWithProfiles(`sip:+12025550100@ingress.example;tag=second`, profiles), "bare header tags do not become identity evidence")
	u, ok := parseCorrelationURI(`<sip:Alice;department=sales@ingress.example>`)
	require.True(t, ok)
	require.Equal(t, "Alice;department=sales", u.user)
	require.Empty(t, u.params)
	for _, value := range []string{`<tel:+12025550100;phone-context=local.example>`, `<tel:1234>`, `<tel:+12025550100;ext>`, `<sip:1234@outside.example;ext=1;isub=2>`, `<sip:1234@outside.example;phone-context=+>`, `<sip:1234@outside.example;ext=abc>`} {
		require.Empty(t, correlationIdentityWithProfiles(value, profiles), value)
	}
	require.Empty(t, correlationIdentityWithProfiles(`<sip:`+strings.Repeat("1", 129)+`@ingress.example>`, profiles))
}

func TestCorrelationIdentityProfilesExplicitAlphanumericRoutingPrefixes(t *testing.T) {
	p := testIdentityProfile()
	p.RewriteRules = []CorrelationIdentityRewrite{{Pattern: `^ROUTE([0-9]+)$`, Replacement: `+${1}`}}
	profiles, err := compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{p})
	require.NoError(t, err)
	canonical := correlationIdentityWithProfiles(`<tel:+12025550100>`, profiles)
	require.NotEmpty(t, canonical)
	require.Equal(t, canonical, correlationIdentityWithProfiles(`<sip:ROUTE12025550100@ingress.example>`, profiles))
	require.Equal(t, canonical, correlationIdentityWithProfiles(`<sip:ROUTE12025550100@egress.example;user=phone>`, profiles))
	for _, value := range []string{`<sip:ROUTE12025550100@outside.example>`, `<sip:Alice12025550100@ingress.example>`, `<sip:route12025550100@ingress.example>`} {
		u, ok := parseCorrelationURI(value)
		require.True(t, ok)
		require.Equal(t, correlationExactURIKey(u), correlationIdentityWithProfiles(value, profiles), value)
		require.NotEqual(t, canonical, correlationIdentityWithProfiles(value, profiles), value)
	}
	require.Empty(t, correlationIdentityWithProfiles(`<sip:OTHER12025550100@ingress.example;user=phone>`, profiles))
	p.AllowNumericSIP = false
	profiles, err = compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{p})
	require.NoError(t, err)
	unmatched := `<sip:ROUTE12025550100@ingress.example>`
	u, ok := parseCorrelationURI(unmatched)
	require.True(t, ok)
	require.Equal(t, correlationExactURIKey(u), correlationIdentityWithProfiles(unmatched, profiles), "explicit rewrite still requires telephone interpretation permission")
	require.Equal(t, canonical, correlationIdentityWithProfiles(`<sip:ROUTE12025550100@ingress.example;user=phone>`, profiles))
	p.AllowNumericSIP = true
	p.RewriteRules = append(p.RewriteRules, CorrelationIdentityRewrite{Pattern: `^ROUTE([0-9]+)$`, Replacement: `+44${1}`})
	profiles, err = compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{p})
	require.NoError(t, err)
	require.Empty(t, correlationIdentityWithProfiles(`<sip:ROUTE12025550100@ingress.example>`, profiles), "conflicting explicit routes do not guess")
	p.RewriteRules = []CorrelationIdentityRewrite{{Pattern: `^ROUTE([0-9]+)$`, Replacement: `99${1}`}, {Pattern: `^99([0-9]+)$`, Replacement: `+${1}`}}
	p.AllowBareGlobal = false
	profiles, err = compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{p})
	require.NoError(t, err)
	require.Empty(t, correlationIdentityWithProfiles(`<sip:ROUTE12025550100@ingress.example>`, profiles), "a rewrite chain cannot evade idempotence")
}

func TestCorrelationIdentityProfilesIPv6SIPHosts(t *testing.T) {
	p := testIdentityProfile()
	p.SIPHosts = []string{"[2001:db8::1]", "[2001:db8::2]:5060"}
	profiles, err := compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{p})
	require.NoError(t, err)
	canonical := correlationIdentityWithProfiles(`<tel:+12025550100>`, profiles)
	for _, uri := range []string{`<sip:+12025550100@[2001:db8::1]>`, `<sips:0012025550100@[2001:DB8::1]>`, `<sip:12025550100@[2001:db8::2]:5060>`} {
		require.Equal(t, canonical, correlationIdentityWithProfiles(uri, profiles), uri)
	}
	for _, host := range []string{"2001:db8::1", "2001:db8::1:5060", "[2001:db8::1", "[2001:db8::1]]", "[2001:db8::1]junk", "[2001:db8::1]:", "[2001:db8::1]:+5060", "[2001:db8::1]:65536", "[2001:db8::1]:0", "[fe80::1%eth0]", "[fe80::1%25eth0]:5060", "[192.0.2.1]"} {
		require.Empty(t, correlationIdentityWithProfiles(`<sip:+12025550100@`+host+`>`, profiles), host)
		bad := p
		bad.SIPHosts = []string{host}
		_, err := compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{bad})
		require.Error(t, err, host)
	}
}

func TestCorrelationIdentityProfilesPreserveSIPUserBoundary(t *testing.T) {
	for _, scope := range []string{"scoped", "unscoped"} {
		t.Run(scope, func(t *testing.T) {
			p := testIdentityProfile()
			host := "ingress.example"
			if scope == "unscoped" {
				host = "outside.example"
			}
			profiles, err := compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{p})
			require.NoError(t, err)
			for _, pair := range [][2]string{
				{`<sip:abc;foo=bar@` + host + `>`, `<sip:abc@` + host + `;foo=bar>`},
				{`<sip:Alice;department=sales@` + host + `>`, `<sip:Alice@` + host + `;department=sales>`},
				{`<sip:alice?route=one@` + host + `>`, `<sip:alice?route=two@` + host + `>`},
			} {
				a := correlationIdentityWithProfiles(pair[0], profiles)
				b := correlationIdentityWithProfiles(pair[1], profiles)
				require.NotEmpty(t, a, pair[0])
				require.NotEmpty(t, b, pair[1])
				require.NotEqual(t, a, b, pair)
				for _, uri := range pair {
					u, ok := parseCorrelationURI(uri)
					require.True(t, ok)
					require.Equal(t, correlationExactURIKey(u), correlationIdentityWithProfiles(uri, profiles), uri)
				}
			}
			for _, uri := range []string{`<sip:alice@` + host + `?subject=unsupported>`, `<sip:alice@` + host + `;transport=udp?subject=unsupported>`} {
				require.Empty(t, correlationIdentityWithProfiles(uri, profiles), uri)
			}
		})
	}
	// Exact comparison never splits even a numeric subscriber without permission.
	p := testIdentityProfile()
	p.AllowNumericSIP = false
	profiles, err := compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{p})
	require.NoError(t, err)
	require.NotEqual(t, correlationIdentityWithProfiles(`<sip:1234;foo=bar@ingress.example>`, profiles), correlationIdentityWithProfiles(`<sip:1234@ingress.example;foo=bar>`, profiles))
	// Telephone parameters remain supported after the user boundary is preserved.
	require.Equal(t, correlationIdentityWithProfiles(`<tel:1234;phone-context=local.example>`, profiles), correlationIdentityWithProfiles(`<sip:1234;phone-context=local.example@ingress.example;user=phone>`, profiles))
	p.AllowNumericSIP = true
	p.RewriteRules = []CorrelationIdentityRewrite{{Pattern: `^ROUTE([0-9]+)$`, Replacement: `+${1}`}}
	profiles, err = compileCorrelationIdentityProfiles([]CorrelationIdentityProfile{p})
	require.NoError(t, err)
	require.Equal(t, correlationIdentityWithProfiles(`<tel:+12025550100;ext=12>`, profiles), correlationIdentityWithProfiles(`<sip:ROUTE12025550100;ext=12@ingress.example>`, profiles))
}
func TestCorrelationIdentityUserBoundaryDoesNotMergeWeakRules(t *testing.T) {
	for _, scope := range []string{"scoped", "unscoped"} {
		for _, rule := range []string{"R1", "R2"} {
			for _, syntax := range []string{"semicolon", "question mark"} {
				t.Run(scope+"/"+rule+"/"+syntax, func(t *testing.T) {
					p := testIdentityProfile()
					host := "ingress.example"
					if scope == "unscoped" {
						host = "outside.example"
					}
					cfg := DefaultCallCorrelationConfig()
					cfg.IdentityProfiles = []CorrelationIdentityProfile{p}
					cfg.AddressChaining = rule == "R1"
					cfg.NumberChaining = rule == "R2"
					c, now := newContractCorrelator(t, cfg, nil)
					first := contractInvite("userinfo-first", 0, *now)
					hop := 1
					if rule == "R2" {
						hop = 4
					}
					second := contractInvite("userinfo-second", hop, now.Add(time.Millisecond))
					if syntax == "semicolon" {
						first.VoIPData.To = `<sip:abc;foo=bar@` + host + `>`
						second.VoIPData.To = `<sip:abc@` + host + `;foo=bar>`
					} else {
						first.VoIPData.To = `<sip:alice?route=one@` + host + `>`
						second.VoIPData.To = `<sip:alice?route=two@` + host + `>`
					}
					a := contractResolve(c, first)
					b := contractResolve(c, second)
					require.NotEqual(t, a.CorrelationID, b.CorrelationID)
					require.Empty(t, b.Rule)
				})
			}
		}
	}
}
