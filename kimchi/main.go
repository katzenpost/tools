// kimchi.go - Katzenpost self contained test network.
// Copyright (C) 2017  Yawning Angel.
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
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/hpcloud/tail"
	aServer "github.com/katzenpost/authority/nonvoting/server"
	aConfig "github.com/katzenpost/authority/nonvoting/server/config"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
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
	cfg.Server.Identifier = fmt.Sprintf("%s.example.org", n)
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
	cfg.Debug.ForceIdentityKey = hex.EncodeToString(identity.Bytes())

	aNode := new(aConfig.Node)
	aNode.IdentityKey = identity.PublicKey()
	if isProvider {
		// Enable the thwack interface.
		cfg.Management = new(sConfig.Management)
		cfg.Management.Enable = true

		aNode.Identifier = cfg.Server.Identifier
		s.authProviders = append(s.authProviders, aNode)
		s.providerIdx++
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
	cfg.Debug.ForceIdentityKey = hex.EncodeToString(s.authIdentity.Bytes())

	if err := cfg.FixupAndValidate(); err != nil {
		return err
	}
	s.authConfig = cfg
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

	s := &kimchi{lastPort: basePort + 1}

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

	// XXX: Thwack the users.

	// XXX: Log a bunch of stuff.

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
