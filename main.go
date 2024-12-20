package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

func main() {
	manager, err := NewHardwareKeyManager("/usr/lib/pkcs11/onepin-opensc-pkcs11.so")
	if err != nil {
		panic(err)
	}
	defer manager.Dispose()
	err = manager.FetchKeys()
	if err != nil {
		panic(err)
	}
	err = manager.Login("123456")
	if err != nil {
		panic(err)
	} else {
		fmt.Println("Login successful")
	}

	var agent2 agent.Agent = NewSigningAgent(manager)

	socketPath := "/tmp/ssh-agent.sock"

	// Remove existing socket if present.
	os.RemoveAll(socketPath)

	// Create a Unix socket for the SSH agent.
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	log.Printf("SSH Agent server started at %s\n", socketPath)
	defer os.Remove(socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		// Serve the client connection.
		go func(c net.Conn) {
			defer c.Close()
			log.Printf("Client connected")
			if err := agent.ServeAgent(agent2, c); err != nil {
				if err != io.EOF {
					log.Printf("Error serving agent: %v", err)
				}
			}
		}(conn)
	}
}
