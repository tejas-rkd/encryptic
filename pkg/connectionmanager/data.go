package connectionmanager

import (
	"crypto/rsa"
	"net"

	"gopkg.in/go-playground/validator.v9"
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

var validate *validator.Validate

type Message struct {
	SenderId     int64  `json:"senderId" validate:"required,number"`
	RecieverId   int64  `json:"recieverId" validate:"required,number"`
	EncryptedMsg []byte `json:"encryptedMsg"`
	OpCode       int    `json:"opCode" validate:"number,gte=0,lte=3"`
}

type ConnectionManager struct {
	publicKey   rsa.PublicKey
	privateKey  rsa.PrivateKey
	lPort       int64
	connections map[int64]*Connection
	register    chan *Connection
	unregister  chan *Connection
}

func validateStruct(m Message) error {
	validate = validator.New()
	err := validate.Struct(m)
	if err != nil {
		return err
	}
	return nil
}
