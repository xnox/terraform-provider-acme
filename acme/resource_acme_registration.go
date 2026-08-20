package acme

import (
	"context"
	"log"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/registration"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// resourceACMERegistration returns the current version of the
// acme_registration resource and needs to be updated when the schema
// version is incremented.
func resourceACMERegistration() *schema.Resource { return resourceACMERegistrationV2() }

func resourceACMERegistrationV2() *schema.Resource {
	return &schema.Resource{
		Create:        resourceACMERegistrationCreate,
		Read:          resourceACMERegistrationRead,
		Delete:        resourceACMERegistrationDelete,
		MigrateState:  resourceACMERegistrationMigrateState,
		SchemaVersion: 2,
		StateUpgraders: []schema.StateUpgrader{
			resourceACMERegistrationStateUpgraderV1(),
		},
		Schema: map[string]*schema.Schema{
			"account_key_pem": {
				Type:      schema.TypeString,
				Optional:  true,
				Computed:  true,
				ForceNew:  true,
				Sensitive: true,
				ConflictsWith: []string{
					"account_key_pem_wo",
					"account_key_algorithm",
					"account_key_ecdsa_curve",
					"account_key_rsa_bits",
				},
			},
			"account_key_pem_wo": {
				// Write-only variant of account_key_pem. The value is supplied in
				// the configuration but never written to state, allowing the
				// account key to be sourced from an ephemeral resource without
				// persisting it. Requires Terraform 1.11 or later.
				//
				// When this is used the account key is provided externally, so the
				// registration is not generated and account_key_pem is left empty
				// (the key is never echoed back as an output). The account key is
				// unavailable during refresh and destroy (Terraform provides no
				// config then), so the account cannot be re-resolved on refresh nor
				// deactivated on destroy - see the Read and Delete functions.
				Type:      schema.TypeString,
				Optional:  true,
				WriteOnly: true,
				Sensitive: true,
				ConflictsWith: []string{
					"account_key_pem",
					"account_key_algorithm",
					"account_key_ecdsa_curve",
					"account_key_rsa_bits",
				},
			},
			"account_key_pem_wo_version": {
				// Companion to account_key_pem_wo. Because the write-only value is
				// never stored, Terraform cannot detect when it changes. Increment
				// this integer to signal an account key rotation. As this resource
				// has no update (it is generated once), a change forces a new
				// resource: the account is re-registered under the new key. Note
				// that the previous account is not deactivated, as the old key is
				// not available during the destroy half of the replace.
				Type:         schema.TypeInt,
				Optional:     true,
				ForceNew:     true,
				RequiredWith: []string{"account_key_pem_wo"},
			},
			// https://letsencrypt.org/docs/integration-guide/#supported-key-algorithms
			// NOTE: Our internal functions support more, but we need to restrict to
			// what's listed here for Let's Encrypt Specifically. This also applies
			// to the specific RSA and ECDSA lengths/curves.
			"account_key_algorithm": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice(
					[]string{keyAlgorithmRSA, keyAlgorithmECDSA},
					false,
				),
				Default:       keyAlgorithmECDSA,
				ConflictsWith: []string{"account_key_pem", "account_key_pem_wo"},
			},
			"account_key_ecdsa_curve": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice(
					[]string{keyECDSACurveP256, keyECDSACurveP384},
					false,
				),
				Default:       keyECDSACurveP384,
				ConflictsWith: []string{"account_key_pem", "account_key_pem_wo", "account_key_rsa_bits"},
			},
			"account_key_rsa_bits": {
				Type:          schema.TypeInt,
				Optional:      true,
				ForceNew:      true,
				ValidateFunc:  validation.IntInSlice([]int{2048, 3072, 4096}),
				Default:       4096,
				ConflictsWith: []string{"account_key_pem", "account_key_pem_wo", "account_key_ecdsa_curve"},
			},
			"email_address": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"external_account_binding": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"key_id": {
							Type:      schema.TypeString,
							Required:  true,
							Sensitive: true,
							ForceNew:  true,
						},
						"hmac_base64": {
							Type:      schema.TypeString,
							Required:  true,
							Sensitive: true,
							ForceNew:  true,
						},
					},
				},
			},
			"registration_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceACMERegistrationCreate(d *schema.ResourceData, meta any) error {
	// If we have no account key from any source, generate one. accountKeyPEM
	// returns the key from either account_key_pem or the write-only
	// account_key_pem_wo. When the write-only key is in use this is non-empty, so
	// we neither generate a key nor set account_key_pem - the key is provided
	// externally and is never persisted or output.
	if accountKeyPEM(d) == "" {
		privateKeyPem, err := generatePrivateKey(
			d.Get("account_key_algorithm").(string),
			d.Get("account_key_rsa_bits").(int),
			d.Get("account_key_ecdsa_curve").(string),
		)
		if err != nil {
			return err
		}

		d.Set("account_key_pem", privateKeyPem)
	}

	// register and agree to the TOS
	client, _, err := expandACMEClient(d, meta, false)
	if err != nil {
		return err
	}

	var reg *acme.ExtendedAccount
	// If EAB was enabled, register using EAB.
	if v, ok := d.GetOk("external_account_binding"); ok {
		reg, err = client.Registration.RegisterWithExternalAccountBinding(
			context.TODO(),
			registration.RegisterEABOptions{
				TermsOfServiceAgreed: true,
				Kid:                  v.([]any)[0].(map[string]any)["key_id"].(string),
				HmacEncoded:          v.([]any)[0].(map[string]any)["hmac_base64"].(string),
			})
	} else {
		// Normal registration.
		reg, err = client.Registration.Register(
			context.TODO(),
			registration.RegisterOptions{
				TermsOfServiceAgreed: true,
			})
	}

	if err != nil {
		return err
	}

	_, user, err := expandACMEClient(d, meta, true)
	if err != nil {
		return err
	}

	// save the reg
	d.SetId(reg.Location)
	return saveACMERegistration(d, user.Registration)
}

func resourceACMERegistrationRead(d *schema.ResourceData, meta any) error {
	// Resolving the account is an authenticated request that needs the account
	// key. With a write-only key the key is not available during refresh, so we
	// cannot re-resolve; preserve the existing state (registration_url) as-is.
	if accountKeyPEM(d) == "" {
		log.Println("[WARN] no account key available during refresh (write-only key in use); " +
			"skipping account resolution and keeping existing registration state")
		return nil
	}

	_, user, err := expandACMEClient(d, meta, true)
	if err != nil {
		if regGone(err) {
			d.SetId("")
			return nil
		}

		return err
	}

	// save the reg
	return saveACMERegistration(d, user.Registration)
}

func resourceACMERegistrationDelete(d *schema.ResourceData, meta any) error {
	// Deactivating the account is an authenticated request that needs the account
	// key. With a write-only key the key is not available during destroy, so the
	// account cannot be deactivated; remove the resource from state and leave the
	// account in place on the server.
	if accountKeyPEM(d) == "" {
		log.Println("[WARN] no account key available during destroy (write-only key in use); " +
			"removing registration from state without deactivating the account")
		return nil
	}

	client, _, err := expandACMEClient(d, meta, true)
	if err != nil {
		return err
	}

	return client.Registration.DeleteRegistration(context.TODO())
}

func regGone(err error) bool {
	e, ok := err.(*acme.ProblemDetails)
	if !ok {
		return false
	}

	switch {
	case e.HTTPStatus == 400 && e.Type == "urn:ietf:params:acme:error:accountDoesNotExist":
		// As per RFC8555, see: no account exists when onlyReturnExisting
		// is set to true.
		return true

	case e.HTTPStatus == 401 && e.Type == "urn:ietf:params:acme:error:unauthorized":
		// Usually happens when the account has been deactivated. The URN
		// is a bit general for my liking, but it should be fine given
		// the specific nature of the request this error would be
		// returned for.
		//
		// Note that some registries return 401 here versus 403.
		return true

	case e.HTTPStatus == 403 && e.Type == "urn:ietf:params:acme:error:unauthorized":
		// Usually happens when the account has been deactivated. The URN
		// is a bit general for my liking, but it should be fine given
		// the specific nature of the request this error would be
		// returned for.
		return true
	}

	return false
}
