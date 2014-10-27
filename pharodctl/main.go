package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"time"
)

func die(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}

func usage() {
	die("usage: pharodctl ls")
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	client, err := net.Dial("unix", "/tmp/pharod.sock")
	if err != nil {
		die(err.Error())
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = client.Write([]byte(os.Args[1] + "\n"))
	if err != nil {
		die(err.Error())
	}

	clientReader := bufio.NewReader(client)
	for {
		line, err := clientReader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				die(err.Error())
			} else {
				break
			}
		}
		fmt.Print(line)
	}
}
