// main.go - generate mix consensus json document
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
	"path"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx/constants"
)

func MakeDescriptor(name string, layer int, publicKey *ecdh.PublicKey) *pki.MixDescriptor {
	id := [constants.NodeIDLength]byte{}
	_, err := rand.Reader.Read(id[:])
	if err != nil {
		panic(err)
	}
	d := pki.MixDescriptor{
		Nickname:            name,
		ID:                  id,
		LoadWeight:          3,
		EpochATopologyLayer: uint8(layer),
		EpochAPublicKey:     publicKey,
	}
	return &d
}

func main() {
	var mixKeysDir, consensusFile string

	flag.StringVar(&mixKeysDir, "mixKeysDir", "", "mix keys dir")
	flag.StringVar(&consensusFile, "consensusFile", "", "consensus file path")
	flag.Parse()

	type testDesc struct {
		Name  string
		Layer int
	}

	mixes := []testDesc{
		{
			Name:  "nsamix101",
			Layer: 1,
		},
		{
			Name:  "nsamix102",
			Layer: 2,
		},
		{
			Name:  "five_eyes",
			Layer: 3,
		},
		{
			Name:  "gchq123",
			Layer: 1,
		},
		{
			Name:  "fsbspy1",
			Layer: 2,
		},
		{
			Name:  "foxtrot2",
			Layer: 3,
		},
	}

	jsonConsensus := pki.JsonConsensus{
		Descriptors: make([]pki.JsonMixDescriptor, len(mixes)),
	}
	for i, mix := range mixes {
		aPrivKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			panic(err)
		}
		desc := MakeDescriptor(mix.Name, mix.Layer, aPrivKey.PublicKey())
		jsonDesc := desc.JsonMixDescriptor()
		jsonConsensus.Descriptors[i] = *jsonDesc
		// write private key to file
		base64PrivateKey := base64.StdEncoding.EncodeToString(aPrivKey.Bytes())
		privateKeyFile := path.Join(mixKeysDir, fmt.Sprintf("%s.mix_privatekey_base64", jsonDesc.Nickname))
		fileMode := os.FileMode(0600)
		ioutil.WriteFile(privateKeyFile, []byte(base64PrivateKey), fileMode)
	}

	// write one json mix network consensus file
	jsonBytes, err := json.MarshalIndent(jsonConsensus, "", "    ")
	if err != nil {
		panic(err)
	}
	fileMode := os.FileMode(0600)
	err = ioutil.WriteFile(consensusFile, jsonBytes, fileMode)
	if err != nil {
		panic(err)
	}
}
