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
	"encoding/hex"
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
	nClient "github.com/katzenpost/authority/nonvoting/client"
	aServer "github.com/katzenpost/authority/nonvoting/server"
	aConfig "github.com/katzenpost/authority/nonvoting/server/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	cLog "github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/thwack"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/minclient"
	"github.com/katzenpost/minclient/block"
	nServer "github.com/katzenpost/server"
	sConfig "github.com/katzenpost/server/config"
)

const (
	logFile     = "kimchi.log"
	basePort    = 30000
	nrNodes     = 6
	nrProviders = 2
	nrClients   = 2
)

var tailConfig = tail.Config{
	Poll:   true,
	Follow: true,
	Logger: tail.DiscardingLogger,
}

var surbKeys = make(map[[constants.SURBIDLength]byte][]byte)

type kimchi struct {
	sync.Mutex
	sync.WaitGroup

	baseDir   string
	logWriter io.Writer

	authConfig    *aConfig.Config
	authIdentity  *eddsa.PrivateKey
	authNodes     []*aConfig.Node
	authProviders []*aConfig.Node
	authClient    pki.Client

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

func (s *kimchi) newMinClient(user, provider string, privateKey *ecdh.PrivateKey) (*minclient.Client, chan interface{}, error) {
	dispName := fmt.Sprintf("minclient-%v@%v", user, provider)
	minclientLogFile := filepath.Join(s.baseDir, fmt.Sprintf("%v.log", dispName))
	minclientLog, err := cLog.New(minclientLogFile, "DEBUG", false)
	lm := minclientLog.GetLogger("callbacks:"+dispName)
	if err != nil {
		log.Fatalf("Failed to create minclient logger: %v", err)
	}
	onlineCh := make(chan interface{}, 1)
	cfg := &minclient.ClientConfig{
		User:        user,
		Provider:    provider,
		LinkKey: privateKey,
		LogBackend:  minclientLog,
		PKIClient:   s.authClient,
		OnConnFn:    func(isConnected bool) {
			lm.Noticef("Peer connection status changed: %v", isConnected)
			select {
			case onlineCh <- isConnected:
			default:
			}
		},
		OnMessageFn: func(b []byte) error {
			lm.Noticef("Received Message: %v", len(b))

			blk, pk, err := block.DecryptBlock(b, privateKey)
			if err != nil {
				lm.Errorf("Failed to decrypt block: %v", err)
				return nil
			}

			lm.Noticef("Sender Public Key: %v", pk)
			lm.Noticef("Message payload: %v", hex.Dump(blk.Payload))

			return nil
		},
		OnACKFn: func(id *[constants.SURBIDLength]byte, b []byte) error {
			lm.Noticef("Received SURB-ACK: %v", len(b))
			lm.Noticef("SURB-ID: %v", hex.EncodeToString(id[:]))

			// surbKeys should have a lock in production code, but lazy.
			k, ok := surbKeys[*id]
			if !ok {
				lm.Errorf("Failed to find SURB SPRP key")
				return nil
			}

			payload, err := sphinx.DecryptSURBPayload(b, k)
			if err != nil {
				lm.Errorf("Failed to decrypt SURB: %v", err)
				return nil
			}
			if utils.CtIsZero(payload) {
				lm.Noticef("SURB Payload: %v bytes of 0x00", len(payload))
			} else {
				lm.Noticef("SURB Payload: %v", hex.Dump(payload))
			}

			return nil
		},
	}
	c, err := minclient.New(cfg)
	if err != nil {
		return nil, nil, err
	}

	go s.logTailer(dispName, minclientLogFile)

	return c, onlineCh, nil
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

	if err = c.PrintfLine("ADD_USER %v %v", user, pubKey); err != nil {
		return err
	}
	if _, _, err = c.ReadResponse(int(thwack.StatusOk)); err != nil {
		return err
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

func sendUnreliableMsg(client *minclient.Client, senderPrivKey *ecdh.PrivateKey, recipient, provider string, recipientPubKey *ecdh.PublicKey, msg []byte) error {
	var msgID [block.MessageIDLength]byte
	rand.Reader.Read(msgID[:])

	blocks, err := block.EncryptMessage(&msgID, msg, senderPrivKey, recipientPubKey)
	if err != nil {
		return err
	}

	return client.SendUnreliableCiphertext(recipient, provider, blocks[0])
}

func sendReliableMsg(client *minclient.Client, senderPrivKey *ecdh.PrivateKey, recipient, provider string, recipientPubKey *ecdh.PublicKey, msg []byte) error {
	var msgID [block.MessageIDLength]byte
	rand.Reader.Read(msgID[:])

	var surbID [constants.SURBIDLength]byte
	rand.Reader.Read(surbID[:])

	blocks, err := block.EncryptMessage(&msgID, msg, senderPrivKey, recipientPubKey)
	if err != nil {
		return err
	}

	k, rtt, err := client.SendCiphertext(recipient, provider, &surbID, blocks[0])
	log.Printf("SendCiphertext: k: %v, rtt: %v, err: %v", hex.EncodeToString(k), rtt, err)
	if err == nil {
		// Should probably lock, but whatever, I'm lazy.
		surbKeys[surbID] = k
	}
	return err
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

	// Create a PKI client instance.
	authClientLogFile := filepath.Join(s.baseDir, "authority-client.log")
	authClientLog, err := cLog.New(authClientLogFile, "DEBUG", false)
	if err != nil {
		log.Fatalf("Failed to create authority client logger: %v", err)
	}
	s.authClient, err = nClient.New(&nClient.Config{
		LogBackend: authClientLog,
		Address:    fmt.Sprintf("127.0.0.1:%d", basePort),
		PublicKey:  s.authIdentity.PublicKey(),
	})
	go s.logTailer("authority-client", authClientLogFile)

	// Launch clients.
	alicePrivateKey, err := ecdh.NewKeypair(rand.Reader)
	aliceProvider := s.authProviders[0].Identifier
	if err = s.thwackUser(s.nodeConfigs[0], "alice", alicePrivateKey.PublicKey()); err != nil {
		log.Fatalf("Failed to add user: %v", err)
	}
	aliceClient, aliceOnlineCh, err := s.newMinClient("alice", aliceProvider, alicePrivateKey)
	if err != nil {
		log.Fatalf("Failed to create alice client: %v", err)
	}
	s.servers = append(s.servers, aliceClient)

	bobPrivateKey, err := ecdh.NewKeypair(rand.Reader)
	bobProvider := s.authProviders[1].Identifier
	if err = s.thwackUser(s.nodeConfigs[1], "bob", bobPrivateKey.PublicKey()); err != nil {
		log.Fatalf("Failed to add user: %v", err)
	}
	bobClient, bobOnlineCh, err := s.newMinClient("bob", bobProvider, bobPrivateKey)
	if err != nil {
		log.Fatalf("Failed to create bob client: %v", err)
	}
	s.servers = append(s.servers, bobClient)

	// Wait for alice and bob to connect, and for the network to fully
	// bootstrap.  The client being connected isn't an indication that the
	// network is up, unfortunately.
	_ = bobOnlineCh
	<-aliceOnlineCh
	time.Sleep(120 * time.Second)

	// Send a test unreliable message.
	msg := []byte(`Mater mara rigani nertaca
Uxella uindape in louci riuri
Briga mara beretor in uaitei tuei
Uoretes silon tuon con deruolami`)
	err = sendUnreliableMsg(aliceClient, alicePrivateKey, "bob", bobProvider, bobPrivateKey.PublicKey(), msg)
	if err != nil {
		log.Printf("Failed to send unreliable message: %v", err)
	}

	// Send a test reliable message.
	msg = []byte(`We have arrived, and it is now that we fulfill our charge.
In fealty to the God-Emperor (our Undying Lord), and by the grace of the Golden Throne, I declare exterminatus upon the Imperial world of Typhon Primaris.
I hereby sign the Death Warrant of an entire world, and consign a million souls to oblivion.
May Imperial justice account in all balance.
The Emperor protects.`)
	err = sendReliableMsg(aliceClient, alicePrivateKey, "bob", bobProvider, bobPrivateKey.PublicKey(), msg)
	if err != nil {
		log.Printf("Failed to send reliable message: %v", err)
	}

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
