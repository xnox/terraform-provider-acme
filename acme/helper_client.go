package acme

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// acmeUser implements acme.User.
type acmeUser struct {
	// The email address for the account.
	Email string

	// The registration resource object.
	Registration *acme.ExtendedAccount

	// The private key for the account.
	key crypto.Signer
}

func (u acmeUser) GetEmail() string {
	return u.Email
}
func (u acmeUser) GetRegistration() *acme.ExtendedAccount {
	return u.Registration
}
func (u acmeUser) GetPrivateKey() crypto.Signer {
	return u.key
}

// accountKeyPEM returns the account private key in PEM form. It is sourced from
// either the stored account_key_pem attribute or, if present and set, the
// write-only account_key_pem_wo attribute (read from the raw config).
//
// It returns an empty string if neither is available. This is expected during
// refresh when a write-only key is in use: write-only values are only supplied
// in the configuration during plan/apply, so they are absent on Read. Callers
// in the read path tolerate this (see expandACMECertifierForRead).
func accountKeyPEM(d *schema.ResourceData) string {
	if v := d.Get("account_key_pem").(string); v != "" {
		return v
	}

	return writeOnlyValue(d, "account_key_pem_wo")
}

// expandACMEUser creates a new instance of an ACME user from set
// email_address and private_key_pem fields, and a registration
// if one exists.
func expandACMEUser(d *schema.ResourceData) (*acmeUser, error) {
	key, err := privateKeyFromPEM([]byte(accountKeyPEM(d)))
	if err != nil {
		return nil, err
	}

	user := &acmeUser{
		key: key,
	}

	// only set these email if it's in the schema.
	if v, ok := d.GetOk("email_address"); ok {
		user.Email = v.(string)
	}

	return user, nil
}

// expandACMEClient creates a connection to an ACME server from resource data,
// and also returns the user.
//
// If loadReg is supplied, the registration information is loaded in to the
// user's registration, if it exists - if the account cannot be resolved by the
// private key, then the appropriate error is returned.
func expandACMEClient(d *schema.ResourceData, meta any, loadReg bool) (*lego.Client, *acmeUser, error) {
	user, err := expandACMEUser(d)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting user data: %s", err.Error())
	}

	client, err := lego.NewClient(expandACMEClient_config(d, meta, user))
	if err != nil {
		return nil, nil, err
	}

	// Populate user's registration resource if needed
	if loadReg {
		user.Registration, err = client.Registration.ResolveAccountByKey(context.TODO())
		if err != nil {
			return nil, nil, err
		}
	}

	return client, user, nil
}

// expandACMECertifierForRead builds a certificate.Certifier suitable for the
// unauthenticated read path - specifically the ARI (renewal info) GET, whose
// certificate identifier is derived from the certificate, not the account. No
// account key is required.
//
// We build the core and certifier directly rather than via lego.NewClient,
// which requires a non-nil account private key. This lets the read path work
// when the account key is unavailable, such as during refresh when a write-only
// key (account_key_pem_wo) is in use and is therefore absent.
func expandACMECertifierForRead(d *schema.ResourceData, meta any) (*certificate.Certifier, error) {
	config := expandACMEClient_config(d, meta, nil)

	// ARI is an unauthenticated GET, so the core is built with no account key id
	// and a nil private key (the JWS signer is never exercised). The directory is
	// still fetched here, as it is needed to locate the renewalInfo endpoint.
	core, err := api.New(config.HTTPClient, config.UserAgent, config.CADirURL, "", nil)
	if err != nil {
		return nil, err
	}

	// A nil resolver is sufficient: it is only used by Obtain/Renew, not by
	// GetRenewalInfo.
	return certificate.NewCertifier(core, nil, certificate.CertifierOptions{
		Timeout: config.Certificate.Timeout,
	}), nil
}

func expandACMEClient_config(d *schema.ResourceData, meta any, user registration.User) *lego.Config {
	config := lego.NewConfig(user)
	config.CADirURL = meta.(*Config).ServerURL

	// Note this function is used by both the registration and certificate
	// resources, but cert timeout is not necessary during registration, so it's
	// okay if it's empty for that.
	if v, ok := d.GetOk("cert_timeout"); ok {
		config.Certificate.Timeout = time.Second * time.Duration(v.(int))
	}

	return config
}
