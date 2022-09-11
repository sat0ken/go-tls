package gotls

import (
	"fmt"
	"log"
	"net"
)

func Conn(server string, port int) net.Conn {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
	if err != nil {
		log.Fatalf("TCP Connection error : %v\n", err)
	}
	return conn
}

func WriteTLS(conn net.Conn, data []byte) ([]TLSProtocol, []byte) {
	buf := make([]byte, 65535)

	conn.Write(data)
	n, _ := conn.Read(buf)

	//fmt.Printf("recv buffer is %x\n", buf[:n])

	return ParseTLSPacket(buf[:n])
}
