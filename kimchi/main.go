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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/textproto"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/hpcloud/tail"
	aServer "github.com/katzenpost/authority/nonvoting/server"
	aConfig "github.com/katzenpost/authority/nonvoting/server/config"
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
	logFile     = "kimchi.log"
	basePort    = 30000
	nrNodes     = 6
	nrProviders = 2
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

func (s *kimchi) genNodeConfig(isProvider bool) error {
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

func (s *kimchi) genAuthConfig() error {
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

func (s *kimchi) newMailProxy(user, provider string, privateKey *ecdh.PrivateKey) (*mailproxy.Proxy, error) {
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

	s := &kimchi{
		lastPort:   basePort + 1,
		recipients: make(map[string]*ecdh.PublicKey),
	}

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

	// Generate the authority identity key.
	if s.authIdentity, err = eddsa.NewKeypair(rand.Reader); err != nil {
		log.Fatalf("Failed to generate authority identity key: %v", err)
	}

	// Generate the provider configs.
	for i := 0; i < nrProviders; i++ {
		if err = s.genNodeConfig(true); err != nil {
			log.Fatalf("Failed to generate provider config: %v", err)
		}
	}

	// Generate the node configs.
	for i := 0; i < nrNodes; i++ {
		if err = s.genNodeConfig(false); err != nil {
			log.Fatalf("Failed to generate node config: %v", err)
		}
	}

	// Generate the authority config, and launch the authority.
	if err = s.genAuthConfig(); err != nil {
		log.Fatalf("Failed to generate authority config: %v", err)
	}
	var svr server
	svr, err = aServer.New(s.authConfig)
	if err != nil {
		log.Fatalf("Failed to launch authority: %v", err)
	}
	s.servers = append(s.servers, svr)
	go s.logTailer("authority", filepath.Join(s.authConfig.Authority.DataDir, s.authConfig.Logging.File))

	// Launch all the nodes.
	for _, v := range s.nodeConfigs {
		svr, err = nServer.New(v)
		if err != nil {
			log.Fatalf("Failed to launch node: %v", err)
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
	aliceProvider := s.authProviders[0].Identifier
	if err = s.thwackUser(s.nodeConfigs[0], "aLiCe", alicePrivateKey.PublicKey()); err != nil {
		log.Fatalf("Failed to add user: %v", err)
	}
	aliceProxy, err := s.newMailProxy("alice", aliceProvider, alicePrivateKey)
	if err != nil {
		log.Fatalf("Failed to create alice client: %v", err)
	}
	s.servers = append(s.servers, aliceProxy)

	// Initialize Bob's mailproxy.
	bobProvider := s.authProviders[1].Identifier
	if err = s.thwackUser(s.nodeConfigs[1], "BoB", bobPrivateKey.PublicKey()); err != nil {
		log.Fatalf("Failed to add user: %v", err)
	}
	bobProxy, err := s.newMailProxy("bob", bobProvider, bobPrivateKey)
	if err != nil {
		log.Fatalf("Failed to create bob client: %v", err)
	}
	s.servers = append(s.servers, bobProxy)

	// Wait for a signal to tear it all down.
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	log.Printf("Received shutdown request.")
	for _, svr = range s.servers {
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
