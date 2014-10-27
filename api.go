package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

const APIUnixSocket = "/tmp/pharod.sock"

func handleAPIClient(c net.Conn) {
	cReader := bufio.NewReader(c)
	defer c.Close()
	cmd, err := cReader.ReadString('\n')
	if cmd == "" && err != nil {
		return
	}

	cmd = strings.TrimSpace(cmd)
	switch cmd {
	case "ls", "listListeners":
		for _, l := range containerListeners {
			fmt.Fprintf(c, "%s.%s: %s:%d -> %s:%d\n", l.DNSName, DnsTld,
				l.Src.IP, l.Src.Port, l.Dest.IP, l.Dest.Port)
		}
	}
}

func startAPI() {
	if _, err := os.Stat(APIUnixSocket); err == nil {
		err = os.Remove(APIUnixSocket)
		if err != nil {
			panic(err)
		}
	}

	server, err := net.Listen("unix", APIUnixSocket)
	if err != nil {
		panic(err)
		return
	}

	err = os.Chmod(APIUnixSocket, os.FileMode(0777))
	if err != nil {
		panic(err)
	}

	for {
		conn, err := server.Accept()
		if err != nil {
			return
		}

		go handleAPIClient(conn)
	}
}
