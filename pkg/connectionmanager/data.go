package connectionmanager

import (
	"crypto/rsa"
	"net"
)

const (
	Certificate      int = 0
	SharedSecret     int = 1
	EncryptedMessage int = 2
	Error            int = 3
)

type Connection struct {
	id     int64
	secret []byte
	socket net.Conn
	data   chan []byte
}

type Message struct {
	SenderId     int64  `json:"senderId"`
	RecieverId   int64  `json:"recieverId"`
	EncryptedMsg []byte `json:"encryptedMsg"`
	OpCode       int    `json:"opCode"`
}

type ConnectionManager struct {
	publicKey   rsa.PublicKey
	privateKey  rsa.PrivateKey
	lPort       int64
	connections map[int64]*Connection
	register    chan *Connection
	unregister  chan *Connection
}
