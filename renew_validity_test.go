package selfsigned

import (
	"context"
	"testing"
	"time"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
)

// certpilot/certpilot#102. A renewal carried no lifetime, so this gateway fell
// back to its own 365-day default: on the published quickstart a 90-day
// certificate renewed into a 365-day one, and nothing reported it. The core now
// restates the lifetime on every renewal, and a renewal is issued for it.
func TestARenewalIsIssuedForTheLifetimeItAsksFor(t *testing.T) {
	for _, days := range []int32{90, 47, 6} {
		resp, err := NewProvider().RenewCertificate(context.Background(), &providerv1.RenewCertificateRequest{
			Domains:      []string{"renew.example.com"},
			KeyType:      "ECDSA",
			KeySize:      256,
			ValidityDays: days,
		})
		if err != nil {
			t.Fatalf("%d days: RenewCertificate: %v", days, err)
		}
		c := resp.Certificate
		got := c.NotAfter.AsTime().Sub(c.NotBefore.AsTime())
		if want := time.Duration(days) * 24 * time.Hour; got < want-time.Hour || got > want+time.Hour {
			t.Errorf("asked for %d days, the renewal lasts %v", days, got.Round(time.Hour))
		}
	}
}

// Zero still means this gateway's default, which is what every renewal meant
// before the field existed: a core that does not send it gets exactly the
// behaviour it had.
func TestARenewalThatAsksForNoLifetimeGetsTheDefault(t *testing.T) {
	resp, err := NewProvider().RenewCertificate(context.Background(), &providerv1.RenewCertificateRequest{
		Domains: []string{"renew.example.com"}, KeyType: "ECDSA", KeySize: 256,
	})
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	c := resp.Certificate
	if got := c.NotAfter.AsTime().Sub(c.NotBefore.AsTime()); got < 364*24*time.Hour || got > 366*24*time.Hour {
		t.Errorf("no lifetime asked for: the renewal lasts %v, want the 365-day default", got.Round(time.Hour))
	}
}
