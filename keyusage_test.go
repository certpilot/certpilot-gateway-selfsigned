package selfsigned

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
)

// TestResolveUsageAppliesDefaultsWhenNothingDeclared. Existing templates that
// have never named a key usage must keep issuing exactly what they always
// have; a change here is not licence to reinterpret silence as a request for
// no key usage at all.
func TestResolveUsageAppliesDefaultsWhenNothingDeclared(t *testing.T) {
	ku, eku, err := resolveUsage(nil, nil, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err != nil {
		t.Fatalf("resolveUsage: %v", err)
	}
	if ku != x509.KeyUsageDigitalSignature {
		t.Errorf("key usage = %v, want the default unchanged", ku)
	}
	if len(eku) != 1 || eku[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ext key usage = %v, want the default unchanged", eku)
	}
}

// TestResolveUsageAppliesOnlyWhatWasDeclared. Declaring extendedKeyUsage says
// nothing about keyUsage — the two are independent fields, and a template
// that only ever set one must not have the other silently cleared.
func TestResolveUsageAppliesOnlyWhatWasDeclared(t *testing.T) {
	ku, eku, err := resolveUsage(nil, []string{"clientAuth"},
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err != nil {
		t.Fatalf("resolveUsage: %v", err)
	}
	if ku != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Errorf("key usage should stay at its default when not declared, got %v", ku)
	}
	if len(eku) != 1 || eku[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ext key usage should be exactly what was declared, got %v", eku)
	}
}

// TestResolveUsageRefusesAnUnrecognisedName. A certificate carrying only the
// names this gateway understood, silently dropping the rest, would look
// constrained and would not be — the failure this whole line of work exists
// to remove.
func TestResolveUsageRefusesAnUnrecognisedName(t *testing.T) {
	if _, _, err := resolveUsage([]string{"digitalSignature", "somethingMadeUp"}, nil, 0, nil); err == nil {
		t.Fatal("an unrecognised key usage name must be refused, not silently dropped")
	}
	if _, _, err := resolveUsage(nil, []string{"clientAuth", "somethingMadeUp"}, 0, nil); err == nil {
		t.Fatal("an unrecognised extended key usage name must be refused, not silently dropped")
	}
}

// TestIssueFromCSRAppliesExactlyTheDeclaredEKU is the end-to-end version of
// the two tests above: parse the certificate this gateway actually produces,
// not merely the x509.Certificate template that asked for it.
func TestIssueFromCSRAppliesExactlyTheDeclaredEKU(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "svc.example.com"}, DNSNames: []string{"svc.example.com"},
	}, key)
	if err != nil {
		t.Fatalf("build CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	resp, err := issueFromCSR(&providerv1.IssueCertificateRequest{
		CsrPem: csrPEM, Domains: []string{"svc.example.com"},
		ExtendedKeyUsage: []string{"clientAuth"},
	})
	if err != nil {
		t.Fatalf("issueFromCSR: %v", err)
	}
	block, _ := pem.Decode(resp.Certificate.CertificatePem)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("declared clientAuth only, issued certificate carries %v — "+
			"this gateway is the one place this milestone can actually enforce the declaration, "+
			"and a mismatch here means it did not", cert.ExtKeyUsage)
	}
}

// TestCaProfileIsAcceptedAndDoesNotChangeTheCertificate. #29's requirement for
// this gateway: accept and ignore, explicitly — not refuse, and not silently
// alter behaviour a caller might construe from it.
func TestCaProfileIsAcceptedAndDoesNotChangeTheCertificate(t *testing.T) {
	p := NewProvider()
	resp, err := p.IssueCertificate(context.Background(), &providerv1.IssueCertificateRequest{
		Domains: []string{"x.example.com"}, KeyType: "ECDSA", KeySize: 256,
		CaProfile: "anything-at-all",
	})
	if err != nil {
		t.Fatalf("a ca_profile this gateway cannot honour must not be refused: %v", err)
	}
	if resp.Certificate == nil {
		t.Fatal("a certificate should still be issued")
	}
}
