# acme_registration

The `acme_registration` resource can be used to create and manage accounts on an
ACME server. Once registered, the same private key that has been used for
registration can be used to request authorizations for certificates.

-> This resource is named `acme_registration` for historical reasons - in the
ACME v1 spec, a _registration_ referred to the account entity.  This resource
name is stable and there are no plans to change it.

-> Keep in mind that when using this resource along with
[`acme_certificate`][resource-certificate] within the same configuration, a
change in the provider-level `server_url` (example: from the Let's Encrypt
staging to production environment) within the same Terraform state will result
in a resource failure, as Terraform will attempt to look for the account in the
wrong CA. Consider different workspaces per environment, and/or using [multiple
provider instances][multiple-provider-instances].

[multiple-provider-instances]: https://www.terraform.io/docs/configuration/providers.html#alias-multiple-provider-configurations
[resource-certificate]: ./certificate.md

## Example

### Basic Example

The following is the most basic example. In this case, the account private key
is managed for you.

```hcl
provider "acme" {
  server_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
}

resource "acme_registration" "reg" {}
```

### Using a Pre-Existing Private Key

The following creates an account off of a private key generated with the
[`tls_private_key`][resource-tls-private-key] resource.

[resource-tls-private-key]: https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/private_key

```hcl
provider "acme" {
  server_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
}

resource "tls_private_key" "private_key" {
  algorithm = "RSA"
}

resource "acme_registration" "reg" {
  account_key_pem = tls_private_key.private_key.private_key_pem
}
```

### Using a write-only account key

To keep the account private key out of Terraform state, supply it via the
[write-only][wo-args] `account_key_pem_wo` argument, sourcing the value from an
[ephemeral resource][ephemeral-resources]. The key is used during apply to
register the account but is never persisted to state, and is **not** echoed back
through the `account_key_pem` attribute (which stays empty).

This requires Terraform 1.11 or later.

```hcl
ephemeral "google_secret_manager_secret_version" "account_key" {
  secret = "acme-account-key"
}

resource "acme_registration" "reg" {
  account_key_pem_wo         = ephemeral.google_secret_manager_secret_version.account_key.secret_data
  account_key_pem_wo_version = 1
  email_address              = "nobody@example.com"
}
```

[wo-args]: https://developer.hashicorp.com/terraform/language/resources/ephemeral/write-only
[ephemeral-resources]: https://developer.hashicorp.com/terraform/language/resources/ephemeral

~> **NOTE:** Because Terraform provides no configuration (and therefore no
write-only values) during refresh or destroy, the account key is unavailable
then. As a result, when `account_key_pem_wo` is used the account is **not**
re-resolved on refresh and is **not** deactivated on destroy - destroying the
resource simply removes it from state and leaves the account in place on the CA.

-> **Rotating the account key:** since the write-only value is never stored,
Terraform cannot detect a change to it. Because this resource has no in-place
update, incrementing `account_key_pem_wo_version` forces a new resource,
registering the account afresh under the new key. The previous account is not
deactivated (its key is not available during the destroy).

#### Argument Reference

~> **NOTE:** All arguments in `acme_registration` force a new resource if
changed.

The resource takes the following arguments:

* `account_key_pem` (Optional) - The private key used to identify the account.
  If not provided (and `account_key_pem_wo` is not used), the key will be
  generated according to the `account_key_algorithm`, `account_key_ecdsa_curve`,
  and `account_key_rsa_bits` settings.
* `account_key_pem_wo` (Optional, [write-only][wo-args]) - A write-only version
  of `account_key_pem`: the account key is supplied in the configuration but
  never written to state. Conflicts with `account_key_pem` and the key
  generation settings. When used, the key must be provided (it is not generated)
  and `account_key_pem` is left empty. Requires Terraform 1.11 or later. See
  [Using a write-only account key](#using-a-write-only-account-key).
* `account_key_pem_wo_version` (Optional) - Companion to `account_key_pem_wo`.
  Increment this integer to signal an account key rotation; since the resource
  has no in-place update, this forces a new resource (re-registration under the
  new key). Can only be set together with `account_key_pem_wo`.
* `account_key_algorithm` (Optional) - The algorithm to use for the private key
  when generating from scratch. Supported settings: `RSA` and `EDCSA`. Default
  settings: `ECDSA`.
* `account_key_ecdsa_curve` (Optional) - ECDSA curve to use for ECDSA key
  types. Supported settings: `P256` and `P384`. Default: `P384`.
* `account_key_rsa_bits` (Optional) - The key length to use for RSA key types.
  Supported settings: `2048`, `3072`, and `4096`. Default: `4096`.
* `email_address` (Optional) - The contact email address for the account.

-> Note that Let's Encrypt no longer sends expiry emails, and only uses this
field for possible email list onboarding (see
<https://letsencrypt.org/2025/06/26/expiration-notification-service-has-ended>).
As such, it is not recommended to set this field when using Let's Encrypt.
Other CAs may or may not require this field - consult the documentation of the
CA you are using in this case.

* `external_account_binding` (Optional) - An external account binding for the
  registration, usually used to link the registration with an account in a
  commercial CA. Sub-options are:
    - `key_id` (Required): The key ID for the external account binding.
    - `hmac_base64` (Required): The base64-encoded message authentication code
      for the external account binding.

#### Attribute Reference

The following attributes are exported:

* `id`: The original full URL of the account.
* `account_key_pem`: The private key used to identify the account (will be
  generated if not provided). This is empty when `account_key_pem_wo` is used,
  as the write-only key is never echoed back.
* `registration_url`: The current full URL of the account.

-> `id` and `registration_url` will usually be the same and will usually only
diverge when migrating protocols, ie: ACME v1 to v2.
