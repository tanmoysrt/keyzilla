package main

import (
	"bytes"
	"errors"
	"log"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SigningAgent implements a custom SSH agent.
type SigningAgent struct {
	KeyManager *HardwareKeyManager
}

// Signers implements agent.Agent.
func (s *SigningAgent) Signers() ([]ssh.Signer, error) {
	panic("operation not supported")
}

// List returns the public keys available in the agent.
func (s *SigningAgent) List() ([]*agent.Key, error) {
	keys := s.KeyManager.Keys
	agentKeys := make([]*agent.Key, len(keys))
	for i, key := range keys {
		data, err := key.Marshal()
		if err != nil {
			log.Println(err)
			return nil, err
		}
		instance, err := key.KeyInstance()
		if err != nil {
			log.Println(err)
			return nil, err
		}
		agentKeys[i] = &agent.Key{
			Format:  instance.Type(),
			Blob:    data,
			Comment: key.Label,
		}
	}

	return agentKeys, nil
}

// Sign calls the external signing mechanism to sign the data.
func (s *SigningAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	// find the key
	keys := s.KeyManager.Keys
	var foundKey *PublicKey
	for _, key2 := range keys {
		data1, err := key2.Marshal()
		if err != nil {
			return nil, err
		}
		data2 := key.Marshal()
		if bytes.Equal(data1, data2) {
			foundKey = &key2
			break
		}
	}

	signatureData, err := s.KeyManager.Sign(*foundKey, data)
	if err != nil {
		return nil, err
	}

	return &ssh.Signature{
		Format: ssh.KeyAlgoRSASHA512,
		Blob:   signatureData,
	}, nil
}

func (s *SigningAgent) Add(key agent.AddedKey) error {
	return errors.New("operation not supported")
}

func (s *SigningAgent) Remove(key ssh.PublicKey) error {
	return errors.New("operation not supported")
}

func (s *SigningAgent) RemoveAll() error {
	return errors.New("operation not supported")
}

func (s *SigningAgent) Lock(passphrase []byte) error {
	return errors.New("operation not supported")
}

func (s *SigningAgent) Unlock(passphrase []byte) error {
	return errors.New("operation not supported")
}

// NewSigningAgent creates a new agent with the given public key and signing function.
func NewSigningAgent(keyManager *HardwareKeyManager) *SigningAgent {
	return &SigningAgent{
		KeyManager: keyManager,
	}
}
