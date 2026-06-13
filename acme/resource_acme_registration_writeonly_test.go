package acme

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// TestAccACMERegistration_writeOnlyAccountKey verifies that an account can be
// registered using the write-only account_key_pem_wo argument, and that the
// key is never persisted to or echoed back from state.
//
// No CheckDestroy is asserted: with a write-only key the account cannot be
// deactivated on destroy (the key is not available then), so the resource is
// simply removed from state and the account is left on the CA.
func TestAccACMERegistration_writeOnlyAccountKey(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: testAccProviders,
		ExternalProviders: testAccExternalProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccACMERegistrationConfigWriteOnly(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						"acme_registration.reg", "id",
						"acme_registration.reg", "registration_url",
					),
					// The write-only key is never written to state, and is not
					// echoed back through the account_key_pem attribute.
					resource.TestCheckNoResourceAttr("acme_registration.reg", "account_key_pem_wo"),
					resource.TestCheckNoResourceAttr("acme_registration.reg", "account_key_pem"),
				),
			},
		},
	})
}

func testAccACMERegistrationConfigWriteOnly() string {
	return fmt.Sprintf(`
provider "acme" {
  server_url = "%s"
}

resource "tls_private_key" "key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "acme_registration" "reg" {
  # Supplied as a write-only value; in real usage this would come from an
  # ephemeral resource. The key is never persisted to acme_registration state.
  account_key_pem_wo         = tls_private_key.key.private_key_pem
  account_key_pem_wo_version = 1
  email_address              = "nobody@%s"
}
`,
		pebbleDirBasic,
		pebbleCertDomain,
	)
}
