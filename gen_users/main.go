// main.go - gen_users
// Copyright (C) 2017  David Anthony Stainton
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/katzenpost/client/util"
	"github.com/katzenpost/client/vault"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
)

// I am a simple key generation program, I perform two tasks:
// 1. write all the public keys to the consensus file AND
// 2. write all the private keys to the keys directory.
func main() {
	var userKeysDir, userConsensusFile string
	flag.StringVar(&userKeysDir, "userKeysDir", "", "user keys dir")
	flag.StringVar(&userConsensusFile, "userConsensusFile", "", "user consensus file")
	flag.Parse()

	passphrase := os.Getenv("MIX_CLIENT_VAULT_PASSPHRASE")
	if len(passphrase) == 0 {
		panic("Aborting because bash env var not set: MIX_CLIENT_VAULT_PASSPHRASE")
	}

	users := []util.Account{
		{
			Name:     "alice",
			Provider: "acme.com",
		},
		{
			Name:     "bob",
			Provider: "nsa.gov",
		},
		{
			Name:     "eve",
			Provider: "gchq.uk",
		},
		{
			Name:     "malory",
			Provider: "fsb.ru",
		},
	}

	userKeyMap := make(map[string]*ecdh.PublicKey)
	for i := 0; i < len(users); i++ {
		privateKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			panic(err)
		}
		privateKeyFile := util.CreateKeyFileName(userKeysDir, "e2e", users[i].Name, users[i].Provider, "private")
		email := fmt.Sprintf("%s@%s", users[i].Name, users[i].Provider)
		v := vault.Vault{
			Type:       "private",
			Email:      email,
			Passphrase: passphrase,
			Path:       privateKeyFile,
		}
		fmt.Printf("priv key %x\n", privateKey.Bytes())
		err = v.Seal(privateKey.Bytes())
		if err != nil {
			panic(err)
		}
		userKeyMap[email] = privateKey.PublicKey()

		// wire protocol keys

		wirePrivateKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			panic(err)
		}
		wirePrivateKeyFile := util.CreateKeyFileName(userKeysDir, "wire", users[i].Name, users[i].Provider, "private")
		wireVault := vault.Vault{
			Type:       "private",
			Email:      email,
			Passphrase: passphrase,
			Path:       wirePrivateKeyFile,
		}
		err = wireVault.Seal(wirePrivateKey.Bytes())
		if err != nil {
			panic(err)
		}
	}

	jsonUserPki := []util.User{}
	for email, key := range userKeyMap {
		base64PublicKey := base64.StdEncoding.EncodeToString(key.Bytes())
		jsonUserPki = append(jsonUserPki, util.User{
			Email: email,
			Key:   base64PublicKey,
		})
	}

	jsonBytes, err := json.MarshalIndent(jsonUserPki, "", "    ")
	if err != nil {
		panic(err)
	}
	fileMode := os.FileMode(0600)
	err = ioutil.WriteFile(userConsensusFile, jsonBytes, fileMode)
	if err != nil {
		panic(err)
	}
}
