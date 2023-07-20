# Encryptic
Encryptic is a P2P messaging system between ***ports***, which is secured by AES using XSalsa20 and Poly1305 to encrypt and authenticate messages.\
For demonstration purpose, we would be using ports on the same system.\
\
**Demo**: https://drive.google.com/file/d/1CkqRaEIzRLdLr_fdsjjEzhWk8tsnHfHQ/view?usp=sharing 

### Getting started:
1. Clone repo
2. `cd encryptic`
3. `go build`
4. `./encryptic <port_no>`
5. Open new terminal and run `./encryptic <other_port_no>`
6. To send message `<port_no>:<message>`. (note: `:` is the seperator between `port` and `message`.)

## Design 
![Flow Diagram](https://github.com/tejas-rkd/encryptic/assets/14247283/3793085a-4c21-4d2e-b883-c92f6370badb)

1. We are using RSA (asymmetric key cryptography) for sharing the shared secret, which is a one time process and hence it's slowness will not be a issue.
2. For message encryption, we are using [NaCl/SecretBox](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox) instead of a more common AES/GCM encryption method. This is an OWASP suggestion.
3. We have added an `opCode` field to the `Message` interface to distingish between the type of messages. Eg. Does message contain RSA Key or Shared secred or Encrypted msg or an Error?
```
type Message struct {
	SenderId     int64  `json:"senderId" validate:"required,number"`
	RecieverId   int64  `json:"recieverId" validate:"required,number"`
	EncryptedMsg []byte `json:"encryptedMsg" validate:"required"`
	OpCode       int    `json:"opCode" validate:"number,gte=0,lte=3"`
	TimeStamp    int64  `json:"timeStamp" validate:"required,number"`
}

const (
	Certificate      int = 0
	SharedSecret     int = 1
	EncryptedMessage int = 2
	Error            int = 3
)
```
4. We have used [Validator](https://pkg.go.dev/github.com/go-playground/validator/v10) framwork to validate incoming messages along with console I/O validation.
5. The `ConnectionManager` construct maintains the list and state of our connections along with the shared secret
```
type ConnectionManager struct {
	publicKey   rsa.PublicKey
	privateKey  rsa.PrivateKey
	lPort       int64
	connections map[int64]*Connection
	register    chan *Connection
	unregister  chan *Connection
}

type Connection struct {
	id     int64
	secret []byte
	socket net.Conn
	data   chan []byte
}
```

## Future Scope
1. Add Logging mechanism. Currently, for quicker development, we are printing errors to console which is a security hazard. System errors should be logged in seperare files and not shown to users.
2. Add unit and integration tests.
3. Better UI experience would be good.
