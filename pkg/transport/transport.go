package transport

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

func DialConnection(port int) (net.Conn, error) {
	connection, err := net.Dial("tcp", "localhost:"+strconv.Itoa(port))
	if err != nil {
		fmt.Println(err)
		return nil, errors.New("unable to dail connection to:" + strconv.Itoa(port))
	}
	return connection, nil
}

func ListenConnection(port int) (net.Listener, error) {
	addr := "localhost:" + strconv.Itoa(int(port))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println(err)
		return nil, errors.New("unable to listen at:" + strconv.Itoa(port))
	}
	return listener, nil
}
