// genconfig.go - Katzenpost self contained test network.
// Copyright (C) 2017  Yawning Angel, David Stainton.
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
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/hpcloud/tail"
	aConfig "github.com/katzenpost/authority/nonvoting/server/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/mailproxy"
	pConfig "github.com/katzenpost/mailproxy/config"
	"github.com/katzenpost/mailproxy/event"
	sConfig "github.com/katzenpost/server/config"
)

const (
	basePort    = 30000
	nrNodes     = 6
	nrProviders = 2
)

var tailConfig = tail.Config{
	Poll:   true,
	Follow: true,
	Logger: tail.DiscardingLogger,
}

type katzenpost struct {
	baseDir   string
	logWriter io.Writer

	authConfig    *aConfig.Config
	authIdentity  *eddsa.PrivateKey
	authNodes     []*aConfig.Node
	authProviders []*aConfig.Node

	nodeConfigs []*sConfig.Config
	lastPort    uint16
	nodeIdx     int
	providerIdx int

	recipients map[string]*ecdh.PublicKey

	servers []server
	tails   []*tail.Tail
}

type server interface {
	Shutdown()
	Wait()
}

func (s *katzenpost) genNodeConfig(isProvider bool) error {
	const serverLogFile = "katzenpost.log"

	n := fmt.Sprintf("node-%d", s.nodeIdx)
	if isProvider {
		n = fmt.Sprintf("provider-%d", s.providerIdx)
	}
	cfg := new(sConfig.Config)

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.Identifier = fmt.Sprintf("%s.eXaMpLe.org", n)
	cfg.Server.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", s.lastPort)}
	cfg.Server.DataDir = filepath.Join(s.baseDir, n)
	os.Mkdir(cfg.Server.DataDir, 0700)
	cfg.Server.IsProvider = isProvider

	// PKI section.
	cfg.PKI = new(sConfig.PKI)
	cfg.PKI.Nonvoting = new(sConfig.Nonvoting)
	cfg.PKI.Nonvoting.Address = fmt.Sprintf("127.0.0.1:%d", basePort)
	cfg.PKI.Nonvoting.PublicKey = s.authIdentity.PublicKey().String()

	// Logging section.
	cfg.Logging = new(sConfig.Logging)
	cfg.Logging.File = serverLogFile
	cfg.Logging.Level = "DEBUG"

	// Debug section.
	cfg.Debug = new(sConfig.Debug)
	cfg.Debug.NumSphinxWorkers = 1
	identity, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return err
	}
	cfg.Debug.IdentityKey = identity

	aNode := new(aConfig.Node)
	aNode.IdentityKey = identity.PublicKey()
	if isProvider {
		// Enable the thwack interface.
		cfg.Management = new(sConfig.Management)
		cfg.Management.Enable = true

		aNode.Identifier = cfg.Server.Identifier
		s.authProviders = append(s.authProviders, aNode)
		s.providerIdx++

		cfg.Provider = new(sConfig.Provider)
		cfg.Provider.AltAddresses = map[string][]string{
			"TCP":   []string{fmt.Sprintf("localhost:%d", s.lastPort)},
			"torv2": []string{"onedaythiswillbea.onion:2323"},
		}

		loopCfg := new(sConfig.Kaetzchen)
		loopCfg.Capability = "loop"
		loopCfg.Endpoint = "+loop"
		cfg.Provider.Kaetzchen = append(cfg.Provider.Kaetzchen, loopCfg)

		keysvrCfg := new(sConfig.Kaetzchen)
		keysvrCfg.Capability = "keyserver"
		keysvrCfg.Endpoint = "+keyserver"
		cfg.Provider.Kaetzchen = append(cfg.Provider.Kaetzchen, keysvrCfg)

		/*
			if s.providerIdx == 1 {
				cfg.Debug.NumProviderWorkers = 10
				cfg.Provider.SQLDB = new(sConfig.SQLDB)
				cfg.Provider.SQLDB.Backend = "pgx"
				cfg.Provider.SQLDB.DataSourceName = "host=localhost port=5432 database=katzenpost sslmode=disable"
				cfg.Provider.UserDB = new(sConfig.UserDB)
				cfg.Provider.UserDB.Backend = sConfig.BackendSQL

				cfg.Provider.SpoolDB = new(sConfig.SpoolDB)
				cfg.Provider.SpoolDB.Backend = sConfig.BackendSQL
			}
		*/
	} else {
		s.authNodes = append(s.authNodes, aNode)
		s.nodeIdx++
	}
	s.nodeConfigs = append(s.nodeConfigs, cfg)
	s.lastPort++
	return cfg.FixupAndValidate()
}

func (s *katzenpost) genAuthConfig() error {
	const authLogFile = "authority.log"

	cfg := new(aConfig.Config)

	// Authority section.
	cfg.Authority = new(aConfig.Authority)
	cfg.Authority.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", basePort)}
	cfg.Authority.DataDir = filepath.Join(s.baseDir, "authority")

	// Logging section.
	cfg.Logging = new(aConfig.Logging)
	cfg.Logging.File = authLogFile
	cfg.Logging.Level = "DEBUG"

	// The node lists.
	cfg.Mixes = s.authNodes
	cfg.Providers = s.authProviders

	// Debug section.
	cfg.Debug = new(aConfig.Debug)
	cfg.Debug.IdentityKey = s.authIdentity

	if err := cfg.FixupAndValidate(); err != nil {
		return err
	}
	s.authConfig = cfg
	return nil
}

func (s *katzenpost) newMailProxy(user, provider string, privateKey *ecdh.PrivateKey) (*mailproxy.Proxy, error) {
	const (
		proxyLogFile = "katzenpost.log"
		authID       = "testAuth"
	)

	cfg := new(pConfig.Config)

	dispName := fmt.Sprintf("mailproxy-%v@%v", user, provider)

	// Proxy section.
	cfg.Proxy = new(pConfig.Proxy)
	cfg.Proxy.POP3Address = fmt.Sprintf("127.0.0.1:%d", s.lastPort)
	s.lastPort++
	cfg.Proxy.SMTPAddress = fmt.Sprintf("127.0.0.1:%d", s.lastPort)
	s.lastPort++
	cfg.Proxy.DataDir = filepath.Join(s.baseDir, dispName)
	cfg.Proxy.EventSink = make(chan event.Event)

	// Logging section.
	cfg.Logging = new(pConfig.Logging)
	cfg.Logging.File = proxyLogFile
	cfg.Logging.Level = "DEBUG"

	// Management section.
	cfg.Management = new(pConfig.Management)
	cfg.Management.Enable = true

	// Authority section.
	cfg.NonvotingAuthority = make(map[string]*pConfig.NonvotingAuthority)
	auth := new(pConfig.NonvotingAuthority)
	auth.Address = fmt.Sprintf("127.0.0.1:%d", basePort)
	auth.PublicKey = s.authIdentity.PublicKey()
	cfg.NonvotingAuthority[authID] = auth

	// Account section.
	acc := new(pConfig.Account)
	acc.User = user
	acc.Provider = provider
	acc.Authority = authID
	acc.LinkKey = privateKey
	acc.IdentityKey = privateKey
	// acc.StorageKey = privateKey
	cfg.Account = append(cfg.Account, acc)

	// UpstreamProxy section.
	/*
		cfg.UpstreamProxy = new(pConfig.UpstreamProxy)
		cfg.UpstreamProxy.Type = "tor+socks5"
		// cfg.UpstreamProxy.Network = "unix"
		// cfg.UpstreamProxy.Address = "/tmp/socks.socket"
		cfg.UpstreamProxy.Network = "tcp"
		cfg.UpstreamProxy.Address = "127.0.0.1:1080"
	*/

	// Recipients section.
	cfg.Recipients = s.recipients

	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}

	p, err := mailproxy.New(cfg)
	if err != nil {
		return nil, err
	}

	go func() {
		for ev := range cfg.Proxy.EventSink {
			log.Printf("%v: Event: %+v", dispName, ev)
			switch e := ev.(type) {
			case *event.KaetzchenReplyEvent:
				// Just assume this is a keyserver query for now.
				if u, k, err := p.ParseKeyQueryResponse(e.Payload); err != nil {
					log.Printf("%v: Keyserver query failed: %v", dispName, err)
				} else {
					log.Printf("%v: Keyserver reply: %v -> %v", dispName, u, k)
				}
			default:
			}
		}
	}()


	return p, nil
}

func main() {
	var err error
	// add nrMixes, nrProviders
	nrNodes := flag.Int("n", 6, "Number of mixes.")
	nrProviders := flag.Int("p", 1, "Number of providers.")
	flag.Parse()
	s := &katzenpost{
		lastPort:   basePort + 1,
		recipients: make(map[string]*ecdh.PublicKey),
	}

	s.baseDir, err = ioutil.TempDir("", "kimchi")
	defer os.RemoveAll(s.baseDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create base directory: %v\n", err)
		os.Exit(-1)
	}

	// Generate the authority identity key.
	if s.authIdentity, err = eddsa.NewKeypair(rand.Reader); err != nil {
		log.Fatalf("Failed to generate authority identity key: %v", err)
	}

	// Generate the provider configs.
	for i := 0; i < *nrProviders; i++ {
		if err = s.genNodeConfig(true); err != nil {
			log.Fatalf("Failed to generate provider config: %v", err)
		}
	}

	// Generate the node configs.
	for i := 0; i < *nrNodes; i++ {
		if err = s.genNodeConfig(false); err != nil {
			log.Fatalf("Failed to generate node config: %v", err)
		}
	}
	// Generate the authority config
	if err = s.genAuthConfig(); err != nil {
		log.Fatalf("Failed to generate authority config: %v", err)
	}
	// write the authority keys to disk
	if err := saveKeys(s.authConfig); err != nil {
		log.Fatalf("%s", err)
	}
	// write the authority configuration to disk
	if err := saveCfg(s.authConfig); err != nil {
		log.Fatalf("Failed to saveCfg of authority with %s", err)
	}
	// write the mixes keys and configs to disk
	for _, v := range s.nodeConfigs {
		if err := saveKeys(v); err != nil {
			log.Fatalf("%s", err)
		}
		if err := saveCfg(v); err != nil {
			log.Fatalf("%s", err)
		}
	}
}

func identifier(cfg interface{}) string {
	switch cfg.(type) {
	case *sConfig.Config:
		return cfg.(*sConfig.Config).Server.Identifier
	case *aConfig.Config:
		return "nonvoting"
	default:
		log.Fatalf("identifier() passed unexpected type")
		return ""
	}
}

func normalizePaths(cfg interface{}) {
	switch cfg.(type) {
	case *sConfig.Config:
		cfg.(*sConfig.Config).Server.DataDir = "/var/lib/katzenpost"
		cfg.(*sConfig.Config).Management.Path = "/var/lib/katzenpost/management_sock"
	case *aConfig.Config:
		cfg.(*aConfig.Config).Authority.DataDir = "/var/lib/katzenpost-authority"
	}
}

func saveKeys(cfg interface{}) (err error) {
	var identityPrivateKeyFile, identityPublicKeyFile string
	identityKey := new(eddsa.PrivateKey)

	pubFile := fmt.Sprintf("%s.public.pem", identifier(cfg))
	privFile := fmt.Sprintf("%s.private.pem", identifier(cfg))

	switch cfg.(type) {
	case *sConfig.Config:
		cfg := cfg.(*sConfig.Config)
		identityPrivateKeyFile = filepath.Join(cfg.Server.DataDir, "identity.private.pem")
		identityPublicKeyFile = filepath.Join(cfg.Server.DataDir, "identity.public.pem")
		if identityKey, err = eddsa.Load(identityPrivateKeyFile, identityPublicKeyFile, rand.Reader); err != nil {
			return err
		}
	case *aConfig.Config:
		cfg := cfg.(*aConfig.Config)
		if cfg.Debug.IdentityKey != nil {
			identityKey.FromBytes(cfg.Debug.IdentityKey.Bytes())
		}
	default:
		log.Fatalf("privIdKeY() passed unexpected type")
	}

	const keyType = "ED25519 PRIVATE KEY"
	blk := &pem.Block{
		Type:  keyType,
		Bytes: identityKey.Bytes(),
	}

	if err = ioutil.WriteFile(privFile, pem.EncodeToMemory(blk), 0600); err != nil {
		return err
	}
	if err = identityKey.PublicKey().ToPEMFile(pubFile); err != nil {
		return err
	}
	return nil
}

func saveCfg(cfg interface{}) error {
	fileName := fmt.Sprintf("%s.toml", identifier(cfg))
	normalizePaths(cfg)
	log.Printf("saveCfg of %s", fileName)
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	// Serialize the descriptor.
	enc := toml.NewEncoder(f)
	return enc.Encode(cfg)
}
