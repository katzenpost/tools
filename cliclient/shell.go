// client.go - Katzenpost demotools cliclient main.
// Copyright (C) 2017  David Stainton
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
	"os"

	"github.com/abiosoft/ishell"
	"github.com/fatih/color"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/mailproxy"
	"github.com/katzenpost/mailproxy/config"
)

const (
	messageTemplate string = "MIME-Version: 1.0\nDate: %v\nSubject: %v\nFrom: %v\nTo: %v\nContent-Type: text/plain; charset=\"UTF-8\"\n\n%v"
)

func showHeader(m *mailproxy.Message) string {
	return fmt.Sprintf("SenderID %v\nSenderKey %v\nMessageID %s", m.SenderKey.String(), m.MessageID, m.Payload)
}

type Shell struct {
	ishell *ishell.Shell
	proxy  *mailproxy.Proxy
}

func (s *Shell) Run() {
	// Let ishell do signal handling.
	s.ishell.Interrupt(func(c *ishell.Context, count int, input string) { s.proxy.Shutdown(); s.ishell.Close() })
	s.ishell.Run()
}

func (s *Shell) Halt() {
	s.proxy.Shutdown()
	s.ishell.Close()
}

func NewShell(proxy *mailproxy.Proxy, cfg *config.Config) *Shell {
	shell := &Shell{
		ishell: ishell.New(),
		proxy:  proxy,
	}
	var err error
	var currIdent string = ""
	magenta := color.New(color.FgMagenta).SprintFunc()
	shell.ishell.Println(magenta("KatzenShell"))
	shell.ishell.SetPrompt(magenta(">>> "))
	for identity, _ := range cfg.Recipients {
		c := ishell.Cmd{
			Name: identity,
			Help: fmt.Sprintf("use %s", identity),
			Func: func(c *ishell.Context) {
				currIdent = identity
			},
		}
		c.AddCmd(&ishell.Cmd{
			Name: "identity",
			Help: "recipient identity",
			Func: func(c *ishell.Context) {
				c.Print("Identity: ")
				recipientKey, err := proxy.GetRecipient(identity)
				if err != nil {
					fmt.Fprintf(os.Stderr, "GetRecipient failed: %v\n", err)
					os.Exit(-1)
				}
				c.Println(recipientKey)
			},
		})

		c.AddCmd(&ishell.Cmd{
			Name: "send",
			Help: "send message",
			Func: func(c *ishell.Context) {
				fromIdentity := ""
				if currIdent != "" {
					fromIdentity = currIdent
				} else {
					c.Print("From: ")
					fromIdentity = c.ReadLine()
				}
				toIdentity := identity
				c.Print("Subject: ")
				msgSubject := c.ReadLine()
				c.Print("Message: (ctrl-D to end)\n")
				msgBody := c.ReadMultiLines("\n.\n")
				// XXX sanitize time
				date := "Mon, 42 Jan 4242 42:42:42 +0100"
				testMessage :=
					fmt.Sprintf(messageTemplate,
						date, msgSubject, fromIdentity,
						toIdentity, msgBody)
				_, err = proxy.SendMessage(fromIdentity, toIdentity, []byte(testMessage))
				if err != nil {
					fmt.Fprintf(os.Stderr, "SendMessage failed: %v\n", err)
					os.Exit(-1)
				}
			},
		})

		shell.ishell.AddCmd(&c)
	}

	// register a function for "list" command.
	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "list",
		Help: "list recipients",
		Func: func(c *ishell.Context) {
			// test the ListRecipients method.
			rpmap := proxy.ListRecipients()
			c.Print("Recipients:\n")
			for identity, pubKey := range rpmap {
				c.Printf("%v %v\n", identity, pubKey)
			}
		},
	})

	// register a function for "providers" command.
	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "providers",
		Help: "list provider connections",
		Func: func(c *ishell.Context) {
			for identity := range cfg.Recipients {
				if proxy.IsConnected(identity) {
					fmt.Printf("%v connected\n", identity)
				}
			}
		},
	})

	// register a function for "peek" command.
	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "peek",
		Help: "receive peek",
		Func: func(c *ishell.Context) {
			// test ReceivePeek method.
			msg, err := proxy.ReceivePeek(currIdent)
			if err == nil {
				c.Print(showHeader(msg))
				c.Printf("%s\n", msg.Payload)
			} else {
				fmt.Fprintf(os.Stderr, "ReceivePeek failed: %v\n", err)
			}
		},
	})

	// register a function for "pop" command.
	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "pop",
		Help: "receive pop",
		Func: func(c *ishell.Context) {
			// test ReceivePop method.
			msg, err := proxy.ReceivePop(currIdent)
			if err == nil {
				c.Print(showHeader(msg))
				c.Printf("%s\n", msg.Payload)
			} else {
				fmt.Fprintf(os.Stderr, "ReceivePeek failed: %v\n", err)
			}
		},
	})

	// register a function for "add" command.
	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "add",
		Help: "add recipient",
		Func: func(c *ishell.Context) {
			// test the SetRecipient method.
			c.Print("Recipient Identity: ")
			username := c.ReadLine()
			c.Print("Recipient PubKey: ")
			pubKey := new(ecdh.PublicKey)
			pubKey.FromString(c.ReadLine())
			err := proxy.SetRecipient(username, pubKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "SetRecipient failed: %v\n", err)
				os.Exit(-1)
			}
		},
	})

	// register a function for "remove" command.
	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "rm",
		Help: "remove recipient",
		Func: func(c *ishell.Context) {
			// test the RemoveRecipient method
			c.Print("Recipient to remove: ")
			recipient := c.ReadLine()
			err = proxy.RemoveRecipient(recipient)
			if err != nil {
				fmt.Fprintf(os.Stderr, "RemoveRecipient failed: %v\n", err)
			}

		},
	})

	// register a function for "send" command.
	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "send",
		Help: "send message",
		Func: func(c *ishell.Context) {
			fromIdentity := ""
			if currIdent != "" {
				fromIdentity = currIdent
			} else {
				c.Print("From: ")
				fromIdentity = c.ReadLine()
			}
			c.Print("To: ")
			toIdentity := c.ReadLine()
			c.Print("Subject: ")
			msgSubject := c.ReadLine()
			c.Print("Message: (ctrl-D to end)\n")
			msgBody := c.ReadMultiLines("\n.\n")
			// XXX sanitize time
			date := "Mon, 42 Jan 4242 42:42:42 +0100"
			testMessage := fmt.Sprintf(messageTemplate, date, msgSubject, fromIdentity, toIdentity, msgBody)
			_, err = proxy.SendMessage(fromIdentity, toIdentity, []byte(testMessage))
			if err != nil {
				fmt.Fprintf(os.Stderr, "SendMessage failed: %v\n", err)
				os.Exit(-1)
			}
		},
	})

	// register a function for "pull" command.
	shell.ishell.AddCmd(&ishell.Cmd{
		Name: "pull",
		Help: "drain message queue",
		Func: func(c *ishell.Context) {
			if currIdent != "" {
				for {
					msg, err := proxy.ReceivePop(currIdent)
					if err != nil {
						break
					}
					c.Print(showHeader(msg))
					c.Printf("%s", msg.Payload)
				}
			}
		},
	})
	return shell
}
