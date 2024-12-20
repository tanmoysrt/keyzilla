package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/miekg/pkcs11"
	"golang.org/x/crypto/ssh"
)

func NewError(message string, err error) error {
	log.Printf("[ERROR] %s: %s\n", message, err.Error())
	return err
}

type PublicKey struct {
	ID     []byte
	Object pkcs11.ObjectHandle
	Label  string
	Key    *rsa.PublicKey
}

func (k *PublicKey) OpenSSHFormat() (string, error) {
	opensshPubKey, err := ssh.NewPublicKey(k.Key)
	if err != nil {
		return "", NewError("Failed to convert SSH key to OpenSSH format", err)
	}

	opensshPubKeyString := string(ssh.MarshalAuthorizedKey(opensshPubKey))
	return opensshPubKeyString, nil
}

func (k *PublicKey) Marshal() ([]byte, error) {
	opensshPubKey, err := ssh.NewPublicKey(k.Key)
	if err != nil {
		return nil, NewError("Failed to convert SSH key to OpenSSH format", err)
	}
	return opensshPubKey.Marshal(), nil
}

func (k *PublicKey) KeyInstance() (ssh.PublicKey, error) {
	return ssh.NewPublicKey(k.Key)
}

func (k *PublicKey) PEMFormat() (string, error) {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(k.Key)
	if err != nil {
		return "", NewError("Failed to marshal public key to DER format", err)
	}
	pubKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	}
	return string(pem.EncodeToMemory(pubKeyPEM)), nil
}

type HardwareKeyManager struct {
	loggedIn      bool
	pkcs11Ctx     *pkcs11.Ctx
	pkcs11Session *pkcs11.SessionHandle
	Keys          []PublicKey
}

func NewHardwareKeyManager(module string) (*HardwareKeyManager, error) {
	// check module path
	_, err := os.Stat(module)
	if os.IsNotExist(err) {
		return nil, NewError("Module does not exist", err)
	}
	pkcs11Ctx := pkcs11.New(module)
	err = pkcs11Ctx.Initialize()
	if err != nil {
		return nil, NewError("Failed to initialize PKCS#11 module", err)
	}
	slots, err := pkcs11Ctx.GetSlotList(true)
	if err != nil {
		return nil, NewError("Failed to get slots", err)
	}
	if len(slots) == 0 {
		return nil, NewError("No slots found", err)
	}
	session, err := pkcs11Ctx.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, NewError("Failed to open session", err)
	}

	return &HardwareKeyManager{
		loggedIn:      false,
		pkcs11Ctx:     pkcs11Ctx,
		pkcs11Session: &session,
		Keys:          []PublicKey{},
	}, nil
}

func (manager *HardwareKeyManager) FetchKeys() error {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}

	if err := manager.pkcs11Ctx.FindObjectsInit(*manager.pkcs11Session, template); err != nil {
		return NewError("FindObjectsInit:", err)
	}
	objs, _, err := manager.pkcs11Ctx.FindObjects(*manager.pkcs11Session, 20)
	if err != nil {
		return NewError("FindObjects:", err)
	}
	if err := manager.pkcs11Ctx.FindObjectsFinal(*manager.pkcs11Session); err != nil {
		log.Fatal("FindObjectsFinal:", err)
	}

	for _, obj := range objs {
		value, err := manager.pkcs11Ctx.GetAttributeValue(*manager.pkcs11Session, obj, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		})
		if err != nil {
			return NewError("[WARN] Failed to get attribute value", err)
		}
		keyLabel := value[0].Value
		keyValue := value[1].Value
		keyID := value[2].Value
		publicKey, err := x509.ParsePKCS1PublicKey(keyValue)
		if err != nil {
			return NewError("[WARN] Failed to parse public key", err)
		}

		manager.Keys = append(manager.Keys, PublicKey{
			ID:     keyID,
			Object: obj,
			Label:  string(keyLabel),
			Key:    publicKey,
		})
	}
	return nil
}

func (manager *HardwareKeyManager) Login(pin string) error {
	err := manager.pkcs11Ctx.Login(*manager.pkcs11Session, pkcs11.CKU_USER, pin)
	if err != nil {
		return NewError("Failed to login", err)
	}
	manager.loggedIn = true
	return nil
}

func (manager *HardwareKeyManager) Dispose() {
	if manager.loggedIn && manager.pkcs11Ctx != nil {
		manager.pkcs11Ctx.Logout(*manager.pkcs11Session)
	}
	if manager.pkcs11Ctx != nil {
		manager.pkcs11Ctx.CloseSession(*manager.pkcs11Session)
	}
	manager.pkcs11Ctx.Finalize()
	manager.pkcs11Ctx.Destroy()
}

func (manager *HardwareKeyManager) Sign(key PublicKey, data []byte) ([]byte, error) {
	if !manager.loggedIn {
		return nil, NewError("Not logged in", errors.New("not logged in"))
	}

	// find out the private key
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, key.ID),
	}

	if err := manager.pkcs11Ctx.FindObjectsInit(*manager.pkcs11Session, template); err != nil {
		return nil, NewError("FindObjectsInit:", err)
	}
	privateKeyObjects, _, err := manager.pkcs11Ctx.FindObjects(*manager.pkcs11Session, 1)
	if err != nil {
		return nil, NewError("FindObjects:", err)
	}
	if err := manager.pkcs11Ctx.FindObjectsFinal(*manager.pkcs11Session); err != nil {
		log.Fatal("FindObjectsFinal:", err)
	}

	if len(privateKeyObjects) == 0 {
		return nil, NewError("No private key found", errors.New("no private key found"))
	}

	obj := privateKeyObjects[0]

	// sign
	if err := manager.pkcs11Ctx.SignInit(*manager.pkcs11Session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA512_RSA_PKCS, nil)}, obj); err != nil {
		return nil, NewError("Failed to init encryption", err)
	}
	fmt.Println("Signing data")
	fmt.Println(string(data))
	fmt.Println("ended")
	signedData, err := manager.pkcs11Ctx.Sign(*manager.pkcs11Session, data[:])
	if err != nil {
		return nil, NewError("Failed to sign data", err)
	}
	fmt.Println("signed")
	fmt.Printf("Signature: %x\n", signedData)
	fmt.Println("ended")

	return signedData, nil
}

// GenerateKeyPair creates a new RSA key pair in the hardware security module
func (manager *HardwareKeyManager) GenerateKeyPair(keyID []byte, label string) error {
	if !manager.loggedIn {
		return NewError("Not logged in", errors.New("not logged in"))
	}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keyID)),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}

	mechanism := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
	}

	pubHandle, _, err := manager.pkcs11Ctx.GenerateKeyPair(
		*manager.pkcs11Session,
		mechanism,
		publicKeyTemplate,
		privateKeyTemplate,
	)
	if err != nil {
		return NewError("Failed to generate key pair", err)
	}

	// Fetch the generated public key attributes
	pubAttrs, err := manager.pkcs11Ctx.GetAttributeValue(*manager.pkcs11Session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return NewError("Failed to get public key attributes", err)
	}

	// Create an rsa.PublicKey from the attributes
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(pubAttrs[0].Value),
		E: int(new(big.Int).SetBytes(pubAttrs[1].Value).Int64()),
	}

	// Add the new key to the manager's Keys slice
	manager.Keys = append(manager.Keys, PublicKey{
		ID:     []byte(keyID),
		Object: pubHandle,
		Label:  label,
		Key:    pubKey,
	})

	return nil
}

// RemoveKeyPair removes both public and private keys with the given keyID from the hardware security module
func (manager *HardwareKeyManager) RemoveKeyPair(keyID []byte) error {
	if !manager.loggedIn {
		return NewError("Not logged in", errors.New("not logged in"))
	}

	// Find and destroy the public key
	pubKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	if err := manager.pkcs11Ctx.FindObjectsInit(*manager.pkcs11Session, pubKeyTemplate); err != nil {
		return NewError("FindObjectsInit for public key:", err)
	}
	pubKeyObjects, _, err := manager.pkcs11Ctx.FindObjects(*manager.pkcs11Session, 1)
	if err != nil {
		return NewError("FindObjects for public key:", err)
	}
	if err := manager.pkcs11Ctx.FindObjectsFinal(*manager.pkcs11Session); err != nil {
		return NewError("FindObjectsFinal for public key:", err)
	}

	// Find and destroy the private key
	privKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	if err := manager.pkcs11Ctx.FindObjectsInit(*manager.pkcs11Session, privKeyTemplate); err != nil {
		return NewError("FindObjectsInit for private key:", err)
	}
	privKeyObjects, _, err := manager.pkcs11Ctx.FindObjects(*manager.pkcs11Session, 1)
	if err != nil {
		return NewError("FindObjects for private key:", err)
	}
	if err := manager.pkcs11Ctx.FindObjectsFinal(*manager.pkcs11Session); err != nil {
		return NewError("FindObjectsFinal for private key:", err)
	}

	// Destroy the public key if found
	if len(pubKeyObjects) > 0 {
		err := manager.pkcs11Ctx.DestroyObject(*manager.pkcs11Session, pubKeyObjects[0])
		if err != nil {
			return NewError("Failed to destroy public key", err)
		}
	}

	// Destroy the private key if found
	if len(privKeyObjects) > 0 {
		err := manager.pkcs11Ctx.DestroyObject(*manager.pkcs11Session, privKeyObjects[0])
		if err != nil {
			return NewError("Failed to destroy private key", err)
		}
	}

	// Remove the key from the manager's Keys slice
	for i, key := range manager.Keys {
		if bytes.Equal(key.ID, keyID) {
			manager.Keys = append(manager.Keys[:i], manager.Keys[i+1:]...)
			break
		}
	}

	return nil
}
