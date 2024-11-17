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
	// for _, key := range manager.Keys {
	// 	fmt.Println(key.Label)
	// 	fmt.Println(key.Object)
	// 	fmt.Println(key.OpenSSHFormat())
	// 	fmt.Println(key.PEMFormat())
	// 	// encrypt
	// 	encrypted, err := manager.Sign(key, []byte("hello"))
	// 	if err != nil {
	// 		fmt.Println(err)
	// 	} else {
	// 		fmt.Println(encrypted)
	// 	}
	// }

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

// func main() {
// socketPath := "/tmp/ssh-agent.sock"

// // Remove existing socket if present.
// os.RemoveAll(socketPath)

// // Create a Unix socket for the SSH agent.
// listener, err := net.Listen("unix", socketPath)
// if err != nil {
// 	log.Fatalf("Failed to create listener: %v", err)
// }
// defer listener.Close()

// log.Printf("SSH Agent server started at %s\n", socketPath)
// defer os.Remove(socketPath)

// 	// Example: Use a preloaded public key.
// 	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICiBh1F6d/qJj5uFqc5rt7XIkmaQKefdYcH+EL1KWXW3 ts741127@gmail.com"))
// 	if err != nil {
// 		log.Fatalf("Failed to parse public key: %v", err)
// 	}

// 	// Example signing method: Replace with your actual signing mechanism.
// 	signingMethod := func(data []byte) ([]byte, error) {
// 		privKeyStr := `----`

// 		// sign with ed25519
// 		privateKey, err := ssh.ParseRawPrivateKey([]byte(privKeyStr))
// 		if err != nil {
// 			return nil, err
// 		}

// 		privateKey2 := privateKey.(*ed25519.PrivateKey)
// 		return ed25519.Sign(*privateKey2, data), nil
// 	}

// var agent2 agent.Agent = NewSigningAgent(publicKey, signingMethod)

// for {
// 	conn, err := listener.Accept()
// 	if err != nil {
// 		log.Printf("Failed to accept connection: %v", err)
// 		continue
// 	}

// 	// Serve the client connection.
// 	go func(c net.Conn) {
// 		defer c.Close()
// 		log.Printf("Client connected")
// 		if err := agent.ServeAgent(agent2, c); err != nil {
// 			if err != io.EOF {
// 				log.Printf("Error serving agent: %v", err)
// 			}
// 		}
// 	}(conn)
// }
// }
