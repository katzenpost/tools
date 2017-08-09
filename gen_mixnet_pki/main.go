// main.go - generate static mix pki json document
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

func MakeMixDescriptor(name string, layer int, publicKey *ecdh.PublicKey, ip string, port int) *pki.MixDescriptor {
	id := [constants.NodeIDLength]byte{}
	_, err := rand.Reader.Read(id[:])
	if err != nil {
		panic(err)
	}
	d := pki.MixDescriptor{
		Nickname:        name,
		ID:              id,
		LoadWeight:      3,
		TopologyLayer:   uint8(layer),
		EpochAPublicKey: publicKey,
		Ipv4Address:     ip,
		TcpPort:         port,
	}
	return &d
}

func MakeProviderDescriptor(name string, layer int, publicKey *ecdh.PublicKey, ip string, port int) *pki.ProviderDescriptor {
	d := pki.ProviderDescriptor{
		Name:              name,
		LongtermPublicKey: publicKey,
		Ipv4Address:       ip,
		TcpPort:           port,
	}
	return &d
}

func main() {
	var keysDir, pkiFile string

	flag.StringVar(&keysDir, "keysDir", "", "mix keys dir")
	flag.StringVar(&pkiFile, "mixPKIFile", "", "consensus file path")
	flag.Parse()

	type testDesc struct {
		Name  string
		Layer int
		IP    string
		Port  int
	}

	providers := []testDesc{
		{
			Name:  "acme.com",
			Layer: 1,
			IP:    "127.0.0.1",
			Port:  11240,
		},
		{
			Name:  "nsa.gov",
			Layer: 1,
			IP:    "127.0.0.1",
			Port:  11241,
		},
		{
			Name:  "gchq.uk",
			Layer: 1,
			IP:    "127.0.0.1",
			Port:  11242,
		},
		{
			Name:  "fsb.ru",
			Layer: 1,
			IP:    "127.0.0.1",
			Port:  11243,
		},
	}

	mixes := []testDesc{
		{
			Name:  "nsamix101",
			Layer: 1,
			IP:    "127.0.0.1",
			Port:  11234,
		},
		{
			Name:  "nsamix102",
			Layer: 2,
			IP:    "127.0.0.1",
			Port:  112345,
		},
		{
			Name:  "five_eyes",
			Layer: 3,
			IP:    "127.0.0.1",
			Port:  11236,
		},
		{
			Name:  "gchq123",
			Layer: 1,
			IP:    "127.0.0.1",
			Port:  11237,
		},
		{
			Name:  "fsbspy1",
			Layer: 2,
			IP:    "127.0.0.1",
			Port:  11238,
		},
		{
			Name:  "foxtrot2",
			Layer: 3,
			IP:    "127.0.0.1",
			Port:  11239,
		},
	}

	jsonPKI := pki.JsonStaticPKI{
		MixDescriptors:      make([]pki.JsonMixDescriptor, len(mixes)),
		ProviderDescriptors: make([]pki.JsonProviderDescriptor, len(providers)),
	}
	for i, provider := range providers {
		aPrivKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			panic(err)
		}
		desc := MakeProviderDescriptor(provider.Name, provider.Layer, aPrivKey.PublicKey(), provider.IP, provider.Port)
		jsonDesc := desc.JsonProviderDescriptor()
		jsonPKI.ProviderDescriptors[i] = *jsonDesc
		// write private key to file
		base64PrivateKey := base64.StdEncoding.EncodeToString(aPrivKey.Bytes())
		privateKeyFile := path.Join(keysDir, fmt.Sprintf("%s.provider_privatekey_base64", jsonDesc.Name))
		fileMode := os.FileMode(0600)
		ioutil.WriteFile(privateKeyFile, []byte(base64PrivateKey), fileMode)
	}
	for i, mix := range mixes {
		aPrivKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			panic(err)
		}
		desc := MakeMixDescriptor(mix.Name, mix.Layer, aPrivKey.PublicKey(), mix.IP, mix.Port)
		jsonDesc := desc.JsonMixDescriptor()
		jsonPKI.MixDescriptors[i] = *jsonDesc
		// write private key to file
		base64PrivateKey := base64.StdEncoding.EncodeToString(aPrivKey.Bytes())
		privateKeyFile := path.Join(keysDir, fmt.Sprintf("%s.mix_privatekey_base64", jsonDesc.Nickname))
		fileMode := os.FileMode(0600)
		ioutil.WriteFile(privateKeyFile, []byte(base64PrivateKey), fileMode)
	}

	// write one json mix network consensus file
	jsonBytes, err := json.MarshalIndent(jsonPKI, "", "    ")
	if err != nil {
		panic(err)
	}
	fileMode := os.FileMode(0600)
	err = ioutil.WriteFile(pkiFile, jsonBytes, fileMode)
	if err != nil {
		panic(err)
	}
}
