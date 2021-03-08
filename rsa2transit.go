// (c) 2021 Michael Gmelin <freebsd@grem.de>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Little program to create a Hashicorp(tm) Vault(c)
// backup file from a PEM encoded RSA private key,
// which can be imported into Vault's transit engine
// using the restore endpoint.
//
// It's a hack, use at your own risk.
//
// Example of use:
//
//  openssl genrsa >mykey.pem
//  cat mykey.pem | go run rsa2transit.go -- mykey >mykey.backup
//  cat mykey.backup | vault write transit/restore backup=-
//

package main

import "crypto/rsa"
import "crypto/x509"
import "encoding/pem"
import "encoding/json"
import "encoding/base64"

//import "errors"
import "flag"
import "fmt"
import "io/ioutil"
import "os"
import "time"

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		println("Usage: rsa2transit keyname [hmac_key]")
		os.Exit(1)
	}

	bytes, _ := ioutil.ReadAll(os.Stdin)
	block, _ := pem.Decode(bytes)
	if block == nil {
		println("Couldn't decode PEM")
		os.Exit(1)
	}
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	if key == nil {
		println("Couldn't parse private key")
		os.Exit(1)
	}

	type KeyInfo struct {
		Key               *string         `json:"key"`
		HmacKey           *string         `json:"hmac_key"`
		Time              time.Time       `json:"time"`
		Ecx               *string         `json:"ec_x"`
		Ecy               *string         `json:"ec_y"`
		Ecd               *string         `json:"ec_d"`
		RsaKey            *rsa.PrivateKey `json:"rsa_key"`
		PublicKey         string          `json:"public_key"`
		ConvergentVersion int             `json:"convergent_version"`
		CreationTime      int64           `json:"creation_time"`
	}

	type ArchivedKeys struct {
		Keys []KeyInfo `json:"keys"`
	}

	type BackupInfo struct {
		Time    time.Time `json:"time"`
		Version int       `json:"version"`
	}

	type Policy struct {
		Name                 string             `json:"name"`
		Keys                 map[string]KeyInfo `json:"keys"`
		Derived              bool               `json:"derived"`
		Kdf                  int                `json:"kdf"`
		ConvergentEncryption bool               `json:"convergent_encryption"`
		Exportable           bool               `json:"exportable"`
		MinDecryptionVersion int                `json:"min_decryption_version"`
		MinEncryptionVersion int                `json:"min_encryption_version"`
		LatestVersion        int                `json:"latest_version"`
		ArchiveVersion       int                `json:"archive_version"`
		ArchiveMinVersion    int                `json:"archive_min_version"`
		MinAvailableVersion  int                `json:"min_available_version"`
		DeletionAllowed      bool               `json:"deletion_allowed"`
		ConvergentVersion    int                `json:"convergent_version"`
		Type                 int                `json:"type"`
		BackupInfo           BackupInfo         `json:"backup_info"`
		RestoreInfo          *string            `json:"restore_info"`
		AllowPlaintextBackup bool               `json:"allow_plaintext_backup"`
		VersionTemplate      string             `json:"version_template"`
		StoragePrefix        string             `json:"storage_prefix"`
		ArchivedKeys         ArchivedKeys       `json:"archived_keys"`
	}

	now := time.Now()
	rsa_key_info := KeyInfo{Time: now, RsaKey: key, CreationTime: now.Unix()}

	policy := Policy{
		Name:                 args[0],
		Keys:                 map[string]KeyInfo{"1": rsa_key_info},
		MinDecryptionVersion: 1,
		LatestVersion:        1,
		ArchiveVersion:       1,
		Type:                 3,
		BackupInfo:           BackupInfo{now, 1},
		ArchivedKeys: ArchivedKeys{Keys: []KeyInfo{
			KeyInfo{},
			rsa_key_info,
		}},
	}

	res, _ := json.Marshal(map[string]Policy{"policy": policy})

	// uncomment to get json
	//fmt.Println(string(res))

	sEnc := base64.StdEncoding.EncodeToString([]byte(string(res)))
	fmt.Println(sEnc)
}
