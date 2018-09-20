// kimchi.go - Katzenpost self contained test network.
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
	"bytes"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/textproto"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/hpcloud/tail"
	vServer "github.com/katzenpost/authority/voting/server"
	vConfig "github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/thwack"
	"github.com/katzenpost/mailproxy"
	pConfig "github.com/katzenpost/mailproxy/config"
	"github.com/katzenpost/mailproxy/event"
	nServer "github.com/katzenpost/server"
	sConfig "github.com/katzenpost/server/config"
)

const (
	logFile       = "kimchi.log"
	basePort      = 30000
	nrNodes       = 6
	nrProviders   = 2
	nrAuthorities = 10
)

var tailConfig = tail.Config{
	Poll:   true,
	Follow: true,
	Logger: tail.DiscardingLogger,
}

type kimchi struct {
	sync.Mutex
	sync.WaitGroup

	baseDir   string
	logWriter io.Writer

	votingAuthConfigs []*vConfig.Config

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

func newKimchi(basePort int) *kimchi {
	//[]*sConfig.Config
	k := &kimchi{
		lastPort:    uint16(basePort + 1),
		recipients:  make(map[string]*ecdh.PublicKey),
		nodeConfigs: make([]*sConfig.Config, 0),
	}
	return k
}

func (s *kimchi) initLogging() error {
	logFilePath := filepath.Join(s.baseDir, logFile)
	f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	// Log to both stdout *and* the log file.
	s.logWriter = io.MultiWriter(f, os.Stdout)
	log.SetOutput(s.logWriter)

	return nil
}

func (s *kimchi) genVotingAuthoritiesCfg(numAuthorities int) error {
	parameters := &vConfig.Parameters{
		MixLambda:       1,
		MixMaxDelay:     10000,
		SendLambda:      123,
		SendShift:       12,
		SendMaxInterval: 123456,
	}
	configs := []*vConfig.Config{}

	// initial generation of key material for each authority
	peersMap := make(map[[eddsa.PublicKeySize]byte]*vConfig.AuthorityPeer)
	for i := 0; i < numAuthorities; i++ {
		cfg := new(vConfig.Config)
		cfg.Logging = &vConfig.Logging{
			Disable: false,
			File:    "katzenpost.log",
			Level:   "DEBUG",
		}
		cfg.Parameters = parameters
		cfg.Authority = &vConfig.Authority{
			Identifier: fmt.Sprintf("authority-%v.example.org", i),
			Addresses:  []string{fmt.Sprintf("127.0.0.1:%d", s.lastPort)},
			DataDir:    filepath.Join(s.baseDir, fmt.Sprintf("authority%d", i)),
		}
		s.lastPort += 1
		privateIdentityKey, err := eddsa.NewKeypair(rand.Reader)
		if err != nil {
			return err
		}
		cfg.Debug = &vConfig.Debug{
			IdentityKey:      privateIdentityKey,
			Layers:           3,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		authorityPeer := &vConfig.AuthorityPeer{
			IdentityPublicKey: cfg.Debug.IdentityKey.PublicKey(),
			LinkPublicKey:     cfg.Debug.IdentityKey.PublicKey().ToECDH(),
			Addresses:         cfg.Authority.Addresses,
		}
		peersMap[cfg.Debug.IdentityKey.PublicKey().ByteArray()] = authorityPeer
	}

	// tell each authority about it's peers
	for i := 0; i < numAuthorities; i++ {
		peers := []*vConfig.AuthorityPeer{}
		for id, peer := range peersMap {
			if !bytes.Equal(id[:], configs[i].Debug.IdentityKey.PublicKey().Bytes()) {
				peers = append(peers, peer)
			}
		}
		configs[i].Authorities = peers
	}
	s.votingAuthConfigs = configs
	return nil
}

func (s *kimchi) genNodeConfig(isProvider bool, isVoting bool) error {
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
	cfg.Server.IsProvider = isProvider

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

	if isVoting {
		peers := []*sConfig.Peer{}
		for _, peer := range s.votingAuthConfigs {
			idKey, err := peer.Debug.IdentityKey.PublicKey().MarshalText()
			if err != nil {
				return err
			}

			linkKey, err := peer.Debug.IdentityKey.PublicKey().ToECDH().MarshalText()
			if err != nil {
				return err
			}
			p := &sConfig.Peer{
				Addresses:         peer.Authority.Addresses,
				IdentityPublicKey: string(idKey),
				LinkPublicKey:     string(linkKey),
			}
			if len(peer.Authority.Addresses) == 0 {
				panic("wtf")
			}
			peers = append(peers, p)
		}
		cfg.PKI = &sConfig.PKI{
			Voting: &sConfig.Voting{
				Peers: peers,
			},
		}
	} else {
		panic("wtf")
	}

	if isProvider {
		// Enable the thwack interface.
		cfg.Management = new(sConfig.Management)
		cfg.Management.Enable = true

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
		s.nodeIdx++
	}
	s.nodeConfigs = append(s.nodeConfigs, cfg)
	s.lastPort++
	err = cfg.FixupAndValidate()
	if err != nil {
		return errors.New("genNodeConfig failure on fixupandvalidate")
	}
	return nil
}

// generateWhitelist returns providers, mixes, error
func (s *kimchi) generateVotingWhitelist() ([]*vConfig.Node, []*vConfig.Node, error) {
	mixes := []*vConfig.Node{}
	providers := []*vConfig.Node{}
	for _, nodeCfg := range s.nodeConfigs {
		if nodeCfg.Server.IsProvider {
			provider := &vConfig.Node{
				Identifier:  nodeCfg.Server.Identifier,
				IdentityKey: nodeCfg.Debug.IdentityKey.PublicKey(),
			}
			providers = append(providers, provider)
			continue
		}
		mix := &vConfig.Node{
			IdentityKey: nodeCfg.Debug.IdentityKey.PublicKey(),
		}
		mixes = append(mixes, mix)
	}

	return providers, mixes, nil
}

func (s *kimchi) runVotingAuthorities() error {
	for _, vCfg := range s.votingAuthConfigs {
		server, err := vServer.New(vCfg)
		if err != nil {
			return err
		}
		go s.logTailer(vCfg.Authority.Identifier, filepath.Join(vCfg.Authority.DataDir, vCfg.Logging.File))
		s.servers = append(s.servers, server)
	}
	return nil
}

func (s *kimchi) newMailProxy(user, provider string, privateKey *ecdh.PrivateKey, isVoting bool) (*mailproxy.Proxy, error) {
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

	// Account section.
	acc := new(pConfig.Account)
	acc.User = user
	acc.Provider = provider
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

	go s.logTailer(dispName, filepath.Join(cfg.Proxy.DataDir, proxyLogFile))

	return p, nil
}

func (s *kimchi) thwackUser(provider *sConfig.Config, user string, pubKey *ecdh.PublicKey) error {
	log.Printf("Attempting to add user: %v@%v", user, provider.Server.Identifier)

	sockFn := filepath.Join(provider.Server.DataDir, "management_sock")
	c, err := textproto.Dial("unix", sockFn)
	if err != nil {
		return err
	}
	defer c.Close()

	if _, _, err = c.ReadResponse(int(thwack.StatusServiceReady)); err != nil {
		return err
	}

	for _, v := range []string{
		fmt.Sprintf("ADD_USER %v %v", user, pubKey),
		fmt.Sprintf("SET_USER_IDENTITY %v %v", user, pubKey),
		"QUIT",
	} {
		if err = c.PrintfLine("%v", v); err != nil {
			return err
		}
		if _, _, err = c.ReadResponse(int(thwack.StatusOk)); err != nil {
			return err
		}
	}

	return nil
}

func (s *kimchi) logTailer(prefix, path string) {
	s.Add(1)
	defer s.Done()

	l := log.New(s.logWriter, prefix+" ", 0)
	t, err := tail.TailFile(path, tailConfig)
	defer t.Cleanup()
	if err != nil {
		log.Fatalf("Failed to tail file '%v': %v", path, err)
	}

	s.Lock()
	s.tails = append(s.tails, t)
	s.Unlock()

	for line := range t.Lines {
		l.Print(line.Text)
	}
}

func main() {

	var err error
	var voting = flag.Bool("voting", false, "if set then using voting authorities")
	var votingNum = flag.Int("votingNum", 3, "the number of voting authorities")
	var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	var memprofile = flag.String("memprofile", "", "write memory profile to this file")
	var genOnly = flag.Bool("g", false, "Generate configuration files and exit immediately.")

	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	s := newKimchi(basePort)

	// TODO: Someone that cares enough can use a config file for this, but
	// this is ultimately just for testing.

	// Create the base directory and bring logging online.
	s.baseDir, err = ioutil.TempDir("", "kimchi")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create base directory: %v\n", err)
		os.Exit(-1)
	}
	if err = s.initLogging(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logging: %v\n", err)
		os.Exit(-1)
	}
	log.Printf("Base Directory: %v", s.baseDir)

	now, elapsed, till := epochtime.Now()
	log.Printf("Epoch: %v (Elapsed: %v, Till: %v)", now, elapsed, till)
	if till < epochtime.Period-(3600*time.Second) {
		log.Printf("WARNING: Descriptor publication for the next epoch will FAIL.")
	}

	// Generate the authority configs
	if *voting {
		err := s.genVotingAuthoritiesCfg(*votingNum)
		if err != nil {
			log.Fatalf("getVotingAuthoritiesCfg failed: %s", err)
		}
	} else {
		// generate nonvoting config
		panic("nonvoting authority not yet supported")
	}

	// Generate the provider configs.
	for i := 0; i < nrProviders; i++ {
		if err = s.genNodeConfig(true, *voting); err != nil {
			log.Fatalf("Failed to generate provider config: %v", err)
		}
	}

	// Generate the node configs.
	for i := 0; i < nrNodes; i++ {
		if err = s.genNodeConfig(false, *voting); err != nil {
			log.Fatalf("Failed to generate node config: %v", err)
		}
	}

	if *genOnly {
		for _, v := range s.nodeConfigs {
			v.Debug.GenerateOnly = true
		}
	}

	if *voting {
		// If generate only - set the debug option for each node.
		if *genOnly {
			for _, v := range s.nodeConfigs {
				v.Debug.GenerateOnly = true
			}
			for _, v := range s.votingAuthConfigs {
				v.Debug.GenerateOnly = true
			}
		}

		providerWhitelist, mixWhitelist, err := s.generateVotingWhitelist()
		if err != nil {
			panic(err)
		}
		for _, aCfg := range s.votingAuthConfigs {
			aCfg.Mixes = mixWhitelist
			aCfg.Providers = providerWhitelist
		}
		err = s.runVotingAuthorities()
		if err != nil && !*genOnly {
			panic(err)
		}
		if *genOnly {
			for _, aCfg := range s.votingAuthConfigs {
				aCfg.Debug.GenerateOnly = false
				if err := saveKeys(aCfg); err != nil {
					log.Fatalf("%s", err)
				}
				if err := saveCfg(aCfg); err != nil {
					log.Fatalf("Failed to saveCfg of authority with %s", err)
				}
			}
		}

	} else {
		// nonvoting here
	}

	// Launch all the nodes.
	for _, v := range s.nodeConfigs {
		svr, err := nServer.New(v)
		if err != nil && !*genOnly {
			log.Fatalf("Failed to launch node: %v", err)
		}
		if *genOnly {
			v.Debug.GenerateOnly = false
			if err := saveKeys(v); err != nil {
				log.Fatalf("%s", err)
			}
			if err := saveCfg(v); err != nil {
				log.Fatalf("%s", err)
			}
		}

		s.servers = append(s.servers, svr)
		go s.logTailer(v.Server.Identifier, filepath.Join(v.Server.DataDir, v.Logging.File))
	}

	// Generate the private keys used by the clients in advance so they
	// can know each other.
	alicePrivateKey, _ := ecdh.NewKeypair(rand.Reader)
	bobPrivateKey, _ := ecdh.NewKeypair(rand.Reader)
	s.recipients["alice@provider-0.example.org"] = alicePrivateKey.PublicKey()
	s.recipients["bob@provider-1.example.org"] = bobPrivateKey.PublicKey()

	// Initialize Alice's mailproxy.
	// XXX aliceProvider := s.authProviders[0].Identifier
	if err = s.thwackUser(s.nodeConfigs[0], "aLiCe", alicePrivateKey.PublicKey()); err != nil {
		log.Fatalf("Failed to add user: %v", err)
	}
	// Initialize Bob's mailproxy.
	// XXX bobProvider := s.authProviders[1].Identifier
	if err = s.thwackUser(s.nodeConfigs[1], "BoB", bobPrivateKey.PublicKey()); err != nil {
		log.Fatalf("Failed to add user: %v", err)
	}

	// Wait for a signal to tear it all down.
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	log.Printf("Received shutdown request.")
	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.WriteHeapProfile(f)
		f.Close()
	}

	for _, svr := range s.servers {
		svr.Shutdown()
	}
	log.Printf("All servers halted.")

	// Wait for the log tailers to return.  This typically won't re-log the
	// shutdown sequence, but if people need the logs from that, they will
	// be in each `DataDir` as needed.
	for _, t := range s.tails {
		t.StopAtEOF()
	}
	s.Wait()
	log.Printf("Terminated.")
}

func identifier(cfg interface{}) string {
	switch cfg.(type) {
	case *sConfig.Config:
		return cfg.(*sConfig.Config).Server.Identifier
	case *vConfig.Config:
		return cfg.(*vConfig.Config).Authority.Identifier
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
	case *vConfig.Config:
		cfg.(*vConfig.Config).Authority.DataDir = "/var/lib/katzenpost-authority"
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
	case *vConfig.Config:
		cfg := cfg.(*vConfig.Config)
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
