package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"encryptic/pkg/cryptox"
)

func (manager *ConnectionManager) start() {
	for {
		select {
		case connection := <-manager.register:
			manager.connections[connection.id] = connection
			fmt.Println("[NEW CONNECTION] Addr -", connection.id)
			go manager.receive(connection)
			go manager.send(connection)
		case connection := <-manager.unregister:
			connection.socket.Close()
			_, ok := manager.connections[connection.id]
			if ok {
				close(connection.data)
				delete(manager.connections, connection.id)
				fmt.Println("[CONNECTION CLOSED] Addr -", connection.id)
			}
		}
	}
}

func (manager *ConnectionManager) receive(connection *Connection) {
	for {
		message := make([]byte, 4096)
		length, err := connection.socket.Read(message)
		if err != nil {
			manager.unregister <- connection
			break
		}
		if length > 0 {
			var msg Message
			err := json.Unmarshal(message[:length], &msg)
			if err != nil {
				fmt.Println(err)
			}

			if msg.OpCode == Certificate {
				key := make([]byte, 32)
				_, err := rand.Read(key)
				if err != nil {
					fmt.Println("error:", err)
					return
				}
				connection := dialConnection(int(msg.SenderId))
				conn := &Connection{id: int64(msg.SenderId), secret: key, socket: connection, data: make(chan []byte)}
				manager.register <- conn

				// error handling based on type of key
				pub, err := cryptox.ParseRsaPublicKeyFromPem(msg.EncryptedMsg)
				if err != nil {
					fmt.Println("error:", err)
				}
				encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, nil)
				if err != nil {
					panic(err)
				}
				manager.sendToPort(int(msg.SenderId), SharedSecret, encryptedBytes)
				continue
			}

			if msg.OpCode == SharedSecret {
				keyBytes, err := manager.privateKey.Decrypt(nil, msg.EncryptedMsg, &rsa.OAEPOptions{Hash: crypto.SHA256})
				if err != nil {
					panic(err)
				}
				conn, ok := manager.connections[msg.SenderId]
				if ok {
					conn.secret = keyBytes
					manager.connections[msg.SenderId] = conn
				} else {
					fmt.Println("unable to refill the secret")
				}
				continue
			}

			if msg.OpCode == EncryptedMessage {
				conn, ok := manager.connections[msg.SenderId]
				if !ok {
					panic(err)
				}
				decrypted, err := cryptox.DecryptMessageSecretBox(msg.EncryptedMsg, conn.secret)
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println(string(decrypted))
			}
		}
	}
}

func (manager *ConnectionManager) send(connection *Connection) {
	defer connection.socket.Close()
	for {
		select {
		case message, ok := <-connection.data:
			if !ok {
				return
			}
			connection.socket.Write(message)
		}
	}
}

func (manager *ConnectionManager) listenOnPort() {
	addr := "localhost:" + strconv.Itoa(int(manager.lPort))
	listener, error := net.Listen("tcp", addr)
	if error != nil {
		fmt.Println(error)
	}
	for {
		connection, _ := listener.Accept()
		if error != nil {
			fmt.Println(error)
		}
		conn := &Connection{socket: connection, data: make(chan []byte)}
		go manager.receive(conn)
	}
}

func (manager *ConnectionManager) sendToPort(rPort, opCode int, msg []byte) {

	encMsg := Message{SenderId: int64(manager.lPort), RecieverId: int64(rPort), OpCode: opCode, EncryptedMsg: msg}
	var conn *Connection
	_, ok := manager.connections[int64(rPort)]
	if ok {
		conn = manager.connections[int64(rPort)]
		if opCode == EncryptedMessage {
			encMsg.EncryptedMsg = cryptox.EncryptMessageSecretBox(msg, conn.secret)
		}
	} else {
		connection := dialConnection(rPort)
		conn = &Connection{id: int64(rPort), socket: connection, data: make(chan []byte)}
		// if opCode == Certificate {
		encMsg.OpCode = Certificate
		pubJson, err := cryptox.ExportRsaPublicKeyAsPem(&manager.publicKey)
		if err != nil {
			fmt.Println(err)
		}
		encMsg.EncryptedMsg = pubJson
		// }
		manager.register <- conn
	}
	data, err := json.Marshal(encMsg)
	if err != nil {
		fmt.Println(err)
	}
	conn.data <- data

}

func dialConnection(rPort int) net.Conn {
	connection, err := net.Dial("tcp", "localhost:"+strconv.Itoa(rPort))
	if err != nil {
		fmt.Println(err)
	}
	return connection
}

func main() {

	// The GenerateKey method takes in a reader that returns random bits, and
	// the number of bits
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// The public key is a part of the *rsa.PrivateKey struct
	publicKey := privateKey.PublicKey

	lPort, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println(err)
	}

	manager := ConnectionManager{
		publicKey:   publicKey,
		privateKey:  *privateKey,
		lPort:       int64(lPort),
		connections: make(map[int64]*Connection),
		register:    make(chan *Connection),
		unregister:  make(chan *Connection),
	}

	go manager.start()
	go manager.listenOnPort()

	for {
		reader := bufio.NewReader(os.Stdin)
		message, _ := reader.ReadString('\n')
		msg := strings.Split(message, ":")
		rPort, err := strconv.Atoi(msg[0])
		if err != nil {
			fmt.Println(err)
		}

		manager.sendToPort(rPort, EncryptedMessage, []byte(msg[1]))

	}
}
