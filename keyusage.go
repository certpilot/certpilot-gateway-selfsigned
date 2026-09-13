package selfsigned

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// This gateway is the one place in the reference set where a declared key
// usage or extended key usage is an enforcement feature rather than a
// selection-and-verification one — see #31. It builds every certificate
// itself, so a template's declaration goes straight onto the x509.Certificate
// template rather than being sent to a CA and hoped for.

// keyUsageBits maps this contract's vocabulary — RFC 5280's own field names,
// lowerCamelCase, matching the template store — onto the stdlib's bits.
var keyUsageBits = map[string]x509.KeyUsage{
	"digitalSignature":  x509.KeyUsageDigitalSignature,
	"contentCommitment": x509.KeyUsageContentCommitment, // formerly nonRepudiation
	"keyEncipherment":   x509.KeyUsageKeyEncipherment,
	"dataEncipherment":  x509.KeyUsageDataEncipherment,
	"keyAgreement":      x509.KeyUsageKeyAgreement,
	"keyCertSign":       x509.KeyUsageCertSign,
	"cRLSign":           x509.KeyUsageCRLSign,
	"encipherOnly":      x509.KeyUsageEncipherOnly,
	"decipherOnly":      x509.KeyUsageDecipherOnly,
}

// extKeyUsageValues maps the same vocabulary's extended key usage names.
var extKeyUsageValues = map[string]x509.ExtKeyUsage{
	"serverAuth":      x509.ExtKeyUsageServerAuth,
	"clientAuth":      x509.ExtKeyUsageClientAuth,
	"codeSigning":     x509.ExtKeyUsageCodeSigning,
	"emailProtection": x509.ExtKeyUsageEmailProtection,
	"timeStamping":    x509.ExtKeyUsageTimeStamping,
	"ocspSigning":     x509.ExtKeyUsageOCSPSigning,
	"any":             x509.ExtKeyUsageAny,
}

// translateKeyUsage turns a template's declared names into the bitmask
// x509.Certificate wants, refusing a name this vocabulary does not define
// rather than silently issuing a certificate with less than was declared.
//
// A refusal here is the honest answer: a template that reached issuance with
// an unrecognised key usage name has already got past whatever validation
// exists upstream, and applying only the names this function does recognise
// would produce a certificate that looks constrained and is not — the exact
// failure this milestone exists to remove.
func translateKeyUsage(names []string) (x509.KeyUsage, error) {
	var bits x509.KeyUsage
	for _, name := range names {
		bit, ok := keyUsageBits[name]
		if !ok {
			return 0, fmt.Errorf("%q is not a key usage this gateway recognises (know: %s)",
				name, strings.Join(sortedKeys(keyUsageBits), ", "))
		}
		bits |= bit
	}
	return bits, nil
}

// translateExtKeyUsage is translateKeyUsage's counterpart for extended key
// usage.
func translateExtKeyUsage(names []string) ([]x509.ExtKeyUsage, error) {
	out := make([]x509.ExtKeyUsage, 0, len(names))
	for _, name := range names {
		v, ok := extKeyUsageValues[name]
		if !ok {
			return nil, fmt.Errorf("%q is not an extended key usage this gateway recognises (know: %s)",
				name, strings.Join(sortedKeys(extKeyUsageValues), ", "))
		}
		out = append(out, v)
	}
	return out, nil
}

// sortedKeys names what a map defines, for an error message that has to be
// deterministic to be worth reading twice.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resolveUsage returns what a certificate's template should carry: the
// declared key usage and extended key usage when either was given, and this
// gateway's existing defaults when neither was. A template that declares one
// and not the other still gets the default for the one it left silent —
// declaring extendedKeyUsage says nothing about keyUsage, and treating an
// absent field as "clear this too" would make every existing template that
// only ever set one of the two start minting certificates neither
// clients nor servers can use.
func resolveUsage(
	wantKeyUsage, wantExtKeyUsage []string, defaultKeyUsage x509.KeyUsage, defaultExtKeyUsage []x509.ExtKeyUsage,
) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	keyUsage := defaultKeyUsage
	if len(wantKeyUsage) > 0 {
		var err error
		keyUsage, err = translateKeyUsage(wantKeyUsage)
		if err != nil {
			return 0, nil, err
		}
	}
	extKeyUsage := defaultExtKeyUsage
	if len(wantExtKeyUsage) > 0 {
		var err error
		extKeyUsage, err = translateExtKeyUsage(wantExtKeyUsage)
		if err != nil {
			return 0, nil, err
		}
	}
	return keyUsage, extKeyUsage, nil
}

// logIgnoredProfile is the whole of this gateway's handling of ca_profile.
//
// selfsigned has no profile concept — there is nothing here to select between,
// because this gateway builds the certificate itself rather than asking a CA
// with its own template system. Silently dropping the field would be exactly
// the failure #29 exists to remove: a setting that is accepted and does
// nothing, with nothing anywhere saying so. Logging it is the difference
// between "ignored, and you can see that it was" and "ignored, and you will
// find out from the certificate".
func logIgnoredProfile(profile string) {
	if profile == "" {
		return
	}
	slog.Info("ca_profile was set and is ignored: the self-signed gateway has no profile concept "+
		"and builds every certificate itself", "ca_profile", profile)
}
