// Implementation of a forward-secure, end-to-end encrypted messaging client
// supporting key compromise recovery and out-of-order message delivery.
// Directly inspired by Signal/Double-ratchet protocol but missing a few
// features. No asynchronous handshake support (pre-keys) for example.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: This is the only file you need to modify for this assignment.
// You may add additional support files if desired. You should modify this file
// to implement the intended protocol, but preserve the function signatures
// for the following methods to ensure your implementation will work with
// standard test code:
//
// *NewChatter
// *EndSession
// *InitiateHandshake
// *ReturnHandshake
// *FinalizeHandshake
// *SendMessage
// *ReceiveMessage
//
// In addition, you'll need to keep all of the following structs' fields:
//
// *Chatter
// *Session
// *Message
//
// You may add fields if needed (not necessary) but don't rename or delete
// any existing fields.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import (
	//	"bytes" //un-comment for helpers like bytes.equal
	"encoding/binary"
	"errors"
	"fmt"
	//	"fmt" //un-comment if you want to do any debug printing.
)

// Labels for key derivation

// Label for generating a check key from the initial root.
// Used for verifying the results of a handshake out-of-band.
const HANDSHAKE_CHECK_LABEL byte = 0x01

// Label for ratcheting the main chain of keys
const CHAIN_LABEL = 0x02

// Label for deriving message keys from chain keys.
const KEY_LABEL = 0x03

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys). You should not need to modify this.
type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
	NewSender	bool
}

// Session represents an open session between one chatter and another.
// You should not need to modify this, though you can add additional fields
// if you want to.
type Session struct {
	MyDHRatchet      *KeyPair
	PartnerDHRatchet *PublicKey
	RootChain        *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain     *SymmetricKey
	StaleReceiveKeys map[int]*SymmetricKey
	SendCounter      int
	LastUpdate       int
	ReceiveCounter   int
}

// Message represents a message as sent over an untrusted network.
// The first 5 fields are send unencrypted (but should be authenticated).
// The ciphertext contains the (encrypted) communication payload.
// You should not need to modify this.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme. You should not need to modify this code.
func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// NewChatter creates and initializes a new Chatter object. A long-term
// identity key is created and the map of sessions is initialized.
// You should not need to modify this code.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = NewKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
// All outstanding key material should be zeroized and the session erased.
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("Don't have that session open to tear down")
	}

	c.Sessions[*partnerIdentity].MyDHRatchet.Zeroize()
	c.Sessions[*partnerIdentity].ReceiveChain.Zeroize()
	c.Sessions[*partnerIdentity].RootChain.Zeroize()
	c.Sessions[*partnerIdentity].SendCounter = 0
	c.Sessions[*partnerIdentity].ReceiveCounter = 0
	c.Identity.Zeroize()
	c.Identity.PrivateKey.Zeroize()
	c.Sessions[*partnerIdentity].StaleReceiveKeys = nil
//	c.Sessions[*partnerIdentity].StaleReceiveKeys[]



	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which initiates should be
// the first to choose a new DH ratchet value. Part of this code has been
// provided for you, you will need to fill in the key derivation code.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}
	c.Sessions[*partnerIdentity] = &Session {
		StaleReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet: NewKeyPair(),
	}

	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, nil

}

// ReturnHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. Part of this code has been provided for you, you will
// need to fill in the key derivation code. The partner which calls this
// method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity,
	partnerDHRatchet *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("Already have session open")
	}

	myKey := NewKeyPair()
	gAb := DHCombine(partnerIdentity, &myKey.PrivateKey)
	gaB := DHCombine(partnerDHRatchet, &c.Identity.PrivateKey)
	gab := DHCombine(partnerDHRatchet, &myKey.PrivateKey)
	tempKey := CombineKeys(gAb, gaB, gab)
	simKey := tempKey.DeriveKey(HANDSHAKE_CHECK_LABEL)
	c.Sessions[*partnerIdentity] = &Session{
		StaleReceiveKeys: make(map[int]*SymmetricKey),
		PartnerDHRatchet: partnerDHRatchet,
		MyDHRatchet: myKey,
		RootChain: tempKey,
	}

	c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain
	c.NewSender = false

	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey,
	simKey, nil

//	return nil, nil, errors.New("Not implemented")
}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake. Part of this code has been provided, you will
// need to fill in the key derivation code. The partner which calls this
// method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity,
	partnerDHRatchet *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't finalize session, not yet open")
	}

	myKey := c.Sessions[*partnerIdentity].MyDHRatchet
	gAb := DHCombine(partnerDHRatchet, &c.Identity.PrivateKey)
	gaB := DHCombine(partnerIdentity, &myKey.PrivateKey)
	gab := DHCombine(partnerDHRatchet, &myKey.PrivateKey)
	tempKey := CombineKeys(gAb, gaB, gab)
	simKey := tempKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

	c.Sessions[*partnerIdentity].RootChain = tempKey
	c.Sessions[*partnerIdentity].PartnerDHRatchet = partnerDHRatchet
	c.Sessions[*partnerIdentity].ReceiveChain = c.Sessions[*partnerIdentity].RootChain
	c.NewSender = true


	return simKey, nil

}

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
	plaintext string) (*Message, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't send message to partner with no open session")
	}


	if c.NewSender == true{ //ga2, a2
		c.Sessions[*partnerIdentity].LastUpdate = c.Sessions[*partnerIdentity].SendCounter
		c.Sessions[*partnerIdentity].MyDHRatchet = NewKeyPair()
		newRatchet := DHCombine(c.Sessions[*partnerIdentity].PartnerDHRatchet, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
		c.Sessions[*partnerIdentity].RootChain = CombineKeys(c.Sessions[*partnerIdentity].RootChain, newRatchet)
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
	} else {
		if c.Sessions[*partnerIdentity].SendChain == nil{
			c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain
		}
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].SendChain.DeriveKey(CHAIN_LABEL)
	}
	c.Sessions[*partnerIdentity].SendCounter = c.Sessions[*partnerIdentity].SendCounter + 1
	message := &Message{
		Sender:   &c.Identity.PublicKey,
		Receiver: partnerIdentity,
		IV: NewIV(),
		NextDHRatchet: &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey , //this is correct
		Counter: c.Sessions[*partnerIdentity].SendCounter,
		LastUpdate: c.Sessions[*partnerIdentity].LastUpdate,
	}

	msgKey := c.Sessions[*partnerIdentity].SendChain.DeriveKey(KEY_LABEL)

	c.NewSender = false

	message.Ciphertext = msgKey.AuthenticatedEncrypt(plaintext, message.EncodeAdditionalData(), message.IV)



	return message, nil
}

// ReceiveMessage is used to receive the given message and return the correct
// plaintext. This method is where most of the key derivation, ratcheting
// and out-of-order message handling logic happens.
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}

////// PART 4 ///////
//	late := false
	dif := 0

	c.Sessions[*message.Sender].ReceiveCounter = c.Sessions[*message.Sender].ReceiveCounter + 1

	if message.Counter != c.Sessions[*message.Sender].ReceiveCounter {
		if message.Counter < c.Sessions[*message.Sender].ReceiveCounter { //message is EARLY!
			if _, exists := c.Sessions[*message.Sender].StaleReceiveKeys[message.Counter]; !exists {
				return "ERROR", errors.New("Message has already been seen and decrypted!")
			} else {
				msgKey := c.Sessions[*message.Sender].StaleReceiveKeys[message.Counter]
				c.NewSender = false
				string, _ := msgKey.AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)
				msgKey.Zeroize()
				return string, nil
			}
		}

	if message.Counter > c.Sessions[*message.Sender].ReceiveCounter {
		fmt.Println("Hi!!!!!!!!!!!")// message is LATE
		if c.Sessions[*message.Sender].PartnerDHRatchet != message.NextDHRatchet{
				dif = message.Counter - c.Sessions[*message.Sender].LastUpdate
				c.Sessions[*message.Sender].PartnerDHRatchet = message.NextDHRatchet
				newRatchet := DHCombine(message.NextDHRatchet, &c.Sessions[*message.Sender].MyDHRatchet.PrivateKey)
				c.Sessions[*message.Sender].RootChain = CombineKeys(c.Sessions[*message.Sender].RootChain, newRatchet)
				c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].RootChain.DeriveKey(CHAIN_LABEL)
				msgKey := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(KEY_LABEL)
				c.Sessions[*message.Sender].StaleReceiveKeys[c.Sessions[*message.Sender].LastUpdate] = msgKey
				c.Sessions[*message.Sender].ReceiveCounter = c.Sessions[*message.Sender].LastUpdate + 1
				dif = dif + 1
		}else{
			dif = message.Counter - c.Sessions[*message.Sender].ReceiveCounter
		}
		for i := 0; i < dif; i++ {
			c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
			msgKey := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(KEY_LABEL)
			c.Sessions[*message.Sender].StaleReceiveKeys[c.Sessions[*message.Sender].ReceiveCounter] = msgKey
			c.Sessions[*message.Sender].ReceiveCounter = c.Sessions[*message.Sender].ReceiveCounter + i
			fmt.Println(c.Sessions[*message.Sender].ReceiveCounter)
		}
		c.NewSender = true
		string, _ := c.Sessions[*message.Sender].StaleReceiveKeys[c.Sessions[*message.Sender].LastUpdate].AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)

		//c.Sessions[*message.Sender].StaleReceiveKeys[c.Sessions[*message.Sender].LastUpdate].Zeroize()
		return string, nil
	}



}

////// PART 4 ////////

	if c.Sessions[*message.Sender].PartnerDHRatchet != message.NextDHRatchet {
		c.Sessions[*message.Sender].PartnerDHRatchet = message.NextDHRatchet
		newRatchet := DHCombine(message.NextDHRatchet, &c.Sessions[*message.Sender].MyDHRatchet.PrivateKey) //ga2 b1
		c.Sessions[*message.Sender].RootChain = CombineKeys(c.Sessions[*message.Sender].RootChain, newRatchet)
		c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].RootChain.DeriveKey(CHAIN_LABEL)
	} else {
		if c.Sessions[*message.Sender].ReceiveChain == nil {
			c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].RootChain
		}
		c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
	}
		c.Sessions[*message.Sender].LastUpdate = message.Counter


	msgKey := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(KEY_LABEL)

	c.NewSender = true

	string, _ := msgKey.AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)
	msgKey.Zeroize()
	c.EndSession(message.Sender)
	c.Sessions[*message.Sender].RootChain.Zeroize()
//	c.Sessions[*message.Sender].StaleReceiveKeys = nil
//	c.Sessions[*message.Sender].SendChain.Zeroize()
//	c.Sessions[*message.Sender].ReceiveChain.Zeroize()

	return string, nil
}
