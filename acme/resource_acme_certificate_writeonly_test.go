package acme

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// testAccCheckACMECertificateAttrEmpty asserts that the given attributes are
// empty - treating an absent attribute and one set to "" as equivalent.
func testAccCheckACMECertificateAttrEmpty(n string, attrs ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Can't find ACME certificate: %s", n)
		}
		for _, a := range attrs {
			if v := rs.Primary.Attributes[a]; v != "" {
				return fmt.Errorf("expected %s to be empty, got %q", a, v)
			}
		}
		return nil
	}
}

// TestAccACMECertificate_writeOnlyAccountKey verifies that a certificate can be
// issued using the write-only account_key_pem_wo argument, and that the
// write-only key is never persisted to state.
//
// Note: revoke_certificate_on_destroy must be false here - a write-only account
// key is not available during destroy, so the certificate cannot be revoked
// (see the guard in resourceACMECertificateCustomizeDiff). Destroy at the end of
// the test therefore succeeds without revoking.
func TestAccACMECertificate_writeOnlyAccountKey(t *testing.T) {
	wantEnv := os.Environ()
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviders,
		ExternalProviders: testAccExternalProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccACMECertificateConfigWriteOnly(1, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(standardResourceName, "id", uuidRegexp),
					resource.TestMatchResourceAttr(standardResourceName, "certificate_url", certURLRegexp),
					// Neither the write-only key nor account_key_pem is written to
					// state in this mode (the key is never persisted or echoed back).
					resource.TestCheckNoResourceAttr(standardResourceName, "account_key_pem_wo"),
					resource.TestCheckNoResourceAttr(standardResourceName, "account_key_pem"),
					testAccCheckACMECertificateValid(standardResourceName, "www-wo", "www-wo2"),
					testAccCheckACMECertificateStatus(standardResourceName, certificateStatusValid),
					testAccCheckEnvironNotChanged(wantEnv),
				),
			},
		},
	})
}

// TestAccACMECertificate_writeOnlyAccountKey_rotation verifies that bumping
// account_key_pem_wo_version forces an in-place renewal (the certificate is
// re-issued, so the serial changes) rather than a no-op or a replacement.
func TestAccACMECertificate_writeOnlyAccountKey_rotation(t *testing.T) {
	wantEnv := os.Environ()
	var certSerial string
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviders,
		ExternalProviders: testAccExternalProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccACMECertificateConfigWriteOnly(1, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(standardResourceName, "id", uuidRegexp),
					testAccCheckACMECertificateSaveSerial(&certSerial),
					testAccCheckEnvironNotChanged(wantEnv),
				),
			},
			{
				Config: testAccACMECertificateConfigWriteOnly(2, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckACMECertificateCheckSerialEqual(&certSerial, false),
					testAccCheckEnvironNotChanged(wantEnv),
				),
			},
		},
	})
}

// TestAccACMECertificate_writeOnlyAccountKey_revokeGuard verifies that using a
// write-only account key while leaving revoke_certificate_on_destroy enabled is
// rejected at plan time, rather than failing during destroy.
func TestAccACMECertificate_writeOnlyAccountKey_revokeGuard(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviders,
		ExternalProviders: testAccExternalProviders,
		Steps: []resource.TestStep{
			{
				Config:      testAccACMECertificateConfigWriteOnly(1, true),
				ExpectError: regexp.MustCompile(`revoke_certificate_on_destroy must be set to false`),
			},
		},
	})
}

// TestAccACMECertificate_writeOnlyPrivateKey verifies that a certificate can be
// issued using a write-only private key supplied from an ephemeral resource,
// that the key is never persisted (private_key_pem and certificate_p12 stay
// empty, as with a CSR), and that bumping private_key_pem_wo_version rotates the
// key by forcing a new resource.
func TestAccACMECertificate_writeOnlyPrivateKey(t *testing.T) {
	wantEnv := os.Environ()
	var certSerial string
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviders,
		ExternalProviders: testAccExternalProviders,
		CheckDestroy:      testAccCheckACMECertificateStatus(standardResourceName, certificateStatusRevoked),
		Steps: []resource.TestStep{
			{
				Config: testAccACMECertificateConfigWriteOnlyPrivateKey(1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr(standardResourceName, "id", uuidRegexp),
					resource.TestMatchResourceAttr(standardResourceName, "certificate_url", certURLRegexp),
					testAccCheckACMECertificateValid(standardResourceName, "www-pkwo", "www-pkwo2"),
					// The supplied private key is never persisted, exactly as with a CSR.
					resource.TestCheckNoResourceAttr(standardResourceName, "private_key_pem_wo"),
					testAccCheckACMECertificateAttrEmpty(standardResourceName, "private_key_pem", "certificate_p12"),
					testAccCheckACMECertificateSaveSerial(&certSerial),
					testAccCheckEnvironNotChanged(wantEnv),
				),
			},
			{
				// Bumping private_key_pem_wo_version forces a new resource (a new
				// key and therefore a new certificate).
				Config: testAccACMECertificateConfigWriteOnlyPrivateKey(2),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckACMECertificateCheckSerialEqual(&certSerial, false),
					testAccCheckACMECertificateAttrEmpty(standardResourceName, "private_key_pem", "certificate_p12"),
					testAccCheckEnvironNotChanged(wantEnv),
				),
			},
		},
	})
}

func testAccACMECertificateConfigWriteOnlyPrivateKey(keyVersion int) string {
	return fmt.Sprintf(`
provider "acme" {
  server_url = "%s"
}

variable "email_address" {
  default = "nobody@%s"
}

variable "domain" {
  default = "%s"
}

resource "acme_registration" "reg" {
  email_address = var.email_address
}

ephemeral "tls_private_key" "cert_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "acme_certificate" "certificate" {
  account_key_pem            = acme_registration.reg.account_key_pem
  common_name                = "www-pkwo.${var.domain}"
  subject_alternative_names  = ["www-pkwo2.${var.domain}"]
  private_key_pem_wo         = ephemeral.tls_private_key.cert_key.private_key_pem
  private_key_pem_wo_version = %d

  recursive_nameservers        = ["%s"]
  disable_authoritative_propagation = true

  dns_challenge {
    provider = "exec"
    config = {
      EXEC_PATH              = "%s"
      EXEC_SEQUENCE_INTERVAL = "5"
    }
  }
}
`,
		pebbleDirBasic,
		pebbleCertDomain,
		pebbleCertDomain,
		keyVersion,
		pebbleChallTestDNSSrv,
		pebbleChallTestDNSScriptPath,
	)
}

func testAccACMECertificateConfigWriteOnly(keyVersion int, revokeOnDestroy bool) string {
	return fmt.Sprintf(`
provider "acme" {
  server_url = "%s"
}

variable "email_address" {
  default = "nobody@%s"
}

variable "domain" {
  default = "%s"
}

resource "acme_registration" "reg" {
  email_address = var.email_address
}

resource "acme_certificate" "certificate" {
  # The account key is supplied as a write-only value. In real usage this would
  # come from an ephemeral resource; here we reuse the registration's key so the
  # account exists. The value is never stored in state.
  account_key_pem_wo            = acme_registration.reg.account_key_pem
  account_key_pem_wo_version    = %d
  revoke_certificate_on_destroy = %t

  common_name               = "www-wo.${var.domain}"
  subject_alternative_names = ["www-wo2.${var.domain}"]

  recursive_nameservers        = ["%s"]
  disable_authoritative_propagation = true

  dns_challenge {
    provider = "exec"
    config = {
      EXEC_PATH              = "%s"
      EXEC_SEQUENCE_INTERVAL = "5"
    }
  }
}
`,
		pebbleDirBasic,
		pebbleCertDomain,
		pebbleCertDomain,
		keyVersion,
		revokeOnDestroy,
		pebbleChallTestDNSSrv,
		pebbleChallTestDNSScriptPath,
	)
}
