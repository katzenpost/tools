// main.go - generate static mix pki cbor document
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
	"bytes"
	"errors"
	"flag"

	"github.com/2tvenom/cbor"
	"github.com/katzenpost/client/mix_pki"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/pki"
)

type MixDescriptorSecrets struct {
	LinkPrivKey *ecdh.PrivateKey
	EpocSecrets map[ecdh.PublicKey]*ecdh.PrivateKey
}

func createMixDescriptor(name string, layer uint8, addresses []string, startEpoch, endEpoch uint64) (*pki.MixDescriptor, *MixDescriptorSecrets, error) {
	LinkPrivKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	mixKeys := make(map[uint64]*ecdh.PublicKey)
	EpocSecrets := make(map[ecdh.PublicKey]*ecdh.PrivateKey)
	for i := startEpoch; i < endEpoch+1; i++ {
		mixPrivKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		mixKeys[i] = mixPrivKey.PublicKey()
		pubKey := mixPrivKey.PublicKey()
		EpocSecrets[*pubKey] = mixPrivKey
	}
	secrets := MixDescriptorSecrets{
		LinkPrivKey: LinkPrivKey,
		EpocSecrets: EpocSecrets,
	}
	descriptor := pki.MixDescriptor{
		Name:       name,
		LinkKey:    LinkPrivKey.PublicKey(),
		MixKeys:    mixKeys,
		Addresses:  addresses,
		Layer:      layer,
		LoadWeight: 0,
	}
	return &descriptor, &secrets, nil
}

func newMixPKI() (pki.Client, map[ecdh.PublicKey]*ecdh.PrivateKey, error) {
	type testDesc struct {
		Name  string
		Layer int
		IP    string
		Port  int
	}

	test_providers := []testDesc{
		{
			Name:  "acme.com",
			Layer: 0,
			IP:    "127.0.0.1",
			Port:  11240,
		},
		{
			Name:  "nsa.gov",
			Layer: 0,
			IP:    "127.0.0.1",
			Port:  11241,
		},
		{
			Name:  "gchq.uk",
			Layer: 0,
			IP:    "127.0.0.1",
			Port:  11242,
		},
		{
			Name:  "fsb.ru",
			Layer: 0,
			IP:    "127.0.0.1",
			Port:  11243,
		},
	}

	test_mixes := []testDesc{
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

	layerMax := uint8(3)
	keysMap := make(map[ecdh.PublicKey]*ecdh.PrivateKey)
	staticPKI := mix_pki.NewStaticPKI()
	startEpoch, _, _ := epochtime.Now()
	providers := []*pki.MixDescriptor{}
	mixes := []*pki.MixDescriptor{}
	for _, provider := range test_providers {
		mockAddr := []string{} // XXX fix me?
		descriptor, descriptorSecrets, err := createMixDescriptor(provider.Name, uint8(provider.Layer), mockAddr, startEpoch, startEpoch+3)
		if err != nil {
			return nil, nil, err
		}
		providers = append(providers, descriptor)
		for pubKey, privKey := range descriptorSecrets.EpocSecrets {
			keysMap[pubKey] = privKey
		}
	}
	for _, mix := range test_mixes {
		mockAddr := []string{} // XXX fix me?
		descriptor, descriptorSecrets, err := createMixDescriptor(mix.Name, uint8(mix.Layer), mockAddr, startEpoch, startEpoch+3)
		if err != nil {
			return nil, nil, err
		}
		mixes = append(mixes, descriptor)
		for pubKey, privKey := range descriptorSecrets.EpocSecrets {
			keysMap[pubKey] = privKey
		}
	}

	// for each epoch create a PKI Document and index it by epoch
	for current := startEpoch; current < startEpoch+3+1; current++ {
		pkiDocument := pki.Document{
			Epoch: current,
		}
		// topology
		pkiDocument.Topology = make([][]*pki.MixDescriptor, layerMax+1)
		for i := uint8(0); i < layerMax; i++ {
			pkiDocument.Topology[i] = make([]*pki.MixDescriptor, 0)
		}
		for i := uint8(0); i < layerMax+1; i++ {
			for _, mix := range mixes {
				if mix.Layer == i {
					pkiDocument.Topology[i] = append(pkiDocument.Topology[i], mix)
				}
			}
		}
		// providers
		for _, provider := range providers {
			pkiDocument.Providers = append(pkiDocument.Providers, provider)
		}
		// setup our epoch -> document map
		staticPKI.Set(current, &pkiDocument)
	}
	return staticPKI, keysMap, nil
}

func main() {
	var keysDir, pkiFile string

	flag.StringVar(&keysDir, "keysDir", "", "mix keys dir")
	flag.StringVar(&pkiFile, "mixPKIFile", "", "consensus file path")
	flag.Parse()

	pkiClient, keysMap, err := newMixPKI()
	documents := []pki.Document{}
	epoch, _, _ := epochtime.Now()
	for i := epoch; i < epoch+4; i++ {
		pkiDoc, err := pkiClient.Get(epoch)
		if err != nil {
			panic(err)
		}
		documents = append(documents, *pkiDoc)
	}

	var fileBuff bytes.Buffer
	encoder := cbor.NewEncoder(&fileBuff)
	ok, err := encoder.Marshal(documents)
	if err != nil {
		panic(err)
	}
	if !ok {
		errors.New("wtf")
	}

	fileBuff = bytes.Buffer{}
	encoder = cbor.NewEncoder(&fileBuff)
	ok, err = encoder.Marshal(keysMap)
	if err != nil {
		panic(err)
	}
	if !ok {
		errors.New("wtf")
	}

}
