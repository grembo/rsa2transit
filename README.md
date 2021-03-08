# rsa2transit
Convert RSA private key to HashiCorp Vault transit backup format

## Example

    vault secrets enable transit
    openssl genrsa >mykey.pem
    cat mykey.pem | go run rsa2transit.go -- mykey >mykey.backup
    cat mykey.backup | vault write transit/restore backup=-

## Another Example

    # Enable transit engine
    vault secrets enable transit

    # Generate and import (unprotected) private key
    openssl genrsa | tee mykey.pem |\
      go run rsa2transit.go -- mykey |\
      vault write transit/restore backup=-

    # Create public key
    openssl rsa -in mykey.pem -pubout >mykey.pub

    # Sign snippet using vault
    echo "data to sign" >input
    vault write -field signature transit/sign/mykey/sha2-256 \
      signature_algorithm=pkcs1v15 \
      input=$(cat input | openssl enc -base64) |\
      awk -F: '{print $3}' | openssl enc -d -base64 >signature

    # Verify signature using openssl
    openssl dgst -sha256 -verify mykey.pub -signature signature input

    # Delete key
    vault write transit/keys/mykey/config deletion_allowed=true
    vault delete transit/keys/mykey
