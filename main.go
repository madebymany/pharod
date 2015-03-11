package main

import (
	"flag"
	"fmt"
	"github.com/fsouza/go-dockerclient"
	"github.com/sevlyar/go-daemon"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path"
	"regexp"
	"strings"
	"sync"
)

var sourceAddrs map[string]map[int]*net.TCPAddr
var dnsZone map[string]net.IP
var containerListeners map[string]*Listener
var dockerIP net.IP
var SourceStartIP = net.ParseIP("127.2.2.1")

const DnsTld = "pharod"

var shouldDaemonize = flag.Bool("d", false, "run in background")

type Listener struct {
	DNSName       string
	Src           *net.TCPAddr
	Dest          *net.TCPAddr
	shouldStop    bool
	finished      *sync.WaitGroup
	tcpListener   *net.TCPListener
	newConn       chan net.Conn
	closedConn    chan net.Conn
	closeAllConns chan struct{}
}

func newDockerClient(host string) (client *docker.Client, err error) {
	if os.Getenv("DOCKER_TLS_VERIFY") != "" {
		dockerCertPath := os.Getenv("DOCKER_CERT_PATH")
		if dockerCertPath == "" {
			return nil, fmt.Errorf("docker TLS required, but no DOCKER_CERT_PATH set")
		}

		return docker.NewTLSClient(host,
			path.Join(dockerCertPath, "cert.pem"),
			path.Join(dockerCertPath, "key.pem"),
			path.Join(dockerCertPath, "ca.pem"))
	} else {
		return docker.NewClient(host)
	}
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func containerPortKey(c *docker.Container, p docker.APIPort) string {
	return fmt.Sprintf("%s:%d", c.ID, p.PrivatePort)
}

func addContainer(dockerClient *docker.Client, cid string) (out []*Listener) {
	c, err := dockerClient.InspectContainer(cid)
	if err != nil {
		log.Printf("Getting container info failed for id %s: %s", cid, err)
		return nil
	}
	ports := c.NetworkSettings.PortMappingAPI()

	out = make([]*Listener, 0, len(ports))
	for _, port := range ports {
		key := containerPortKey(c, port)
		if _, ok := containerListeners[key]; ok {
			// already started
			continue
		}
		l, err := ListenerFromContainerAndPort(c, port)
		if err != nil {
			log.Printf("Error creating listener for %v on container %s: %s",
				port, c.ID, err)
			continue
		}
		l.Start()
		containerListeners[key] = l
		dnsZone[l.DNSName] = l.Src.IP
		out = append(out, l)
	}
	return
}

func removeContainer(cid string) {
	for cp, l := range containerListeners {
		if strings.HasPrefix(cp, cid+":") {
			delete(containerListeners, cp)
			delete(dnsZone, l.DNSName)
			delete(sourceAddrs[l.Src.IP.String()], l.Src.Port)
			l.Stop()
		}
	}
}

func main() {
	var err error

	log.SetOutput(os.Stderr)
	flag.Parse()

	currentUser, err := user.Current()
	if err != nil {
		die(err.Error())
	}
	if currentUser.Uid != "0" {
		die("Must be run as root")
	}

	if SourceStartIP == nil {
		panic("SourceStartIPStr not an IP address")
	}

	err = install()
	if err != nil {
		die(err.Error())
	}

	dockerHost := os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		die("DOCKER_HOST not set")
	}

	dockerIpStr := os.Getenv("DOCKER_HOST_IP")
	if dockerIpStr == "" {
		dockerHostUrl, err := url.Parse(dockerHost)
		if err != nil {
			die(fmt.Sprintf("Couldn't parse DOCKER_HOST URL: %v", err))
		}
		dockerIpStr, _, err = net.SplitHostPort(dockerHostUrl.Host)
		if err != nil {
			die(err.Error())
		}
	}

	dockerIpAddr, err := net.ResolveIPAddr("ip", dockerIpStr)
	if err != nil {
		die(fmt.Sprintf("'%s' couldn't be resolved: %v", dockerIpStr, err))
	}
	dockerIP = dockerIpAddr.IP

	if *shouldDaemonize {
		arg0 := os.Args[0]
		if arg0 == "" {
			panic("arg 0 is \"\"")
		} else if !strings.Contains(arg0, "/") {
			die("When daemonizing, pharod must be called with an absolute path, like /usr/bin/pharod")
		}

		dmn := &daemon.Context{
			PidFileName: "/var/run/pharod.pid",
			PidFilePerm: 0644,
			LogFileName: "/var/log/pharod.log",
			LogFilePerm: 0640,
			WorkDir:     "/",
			Umask:       027,
		}
		fmt.Println("Starting Pharod in the background...")
		child, err := dmn.Reborn()
		if err != nil {
			die(err.Error())
		}
		if child != nil {
			fmt.Printf("Started as process %d. Check output in %s\n",
				child.Pid, dmn.LogFileName)
			os.Exit(0)
		}
	}

	log.Println("** Starting Pharod")

	dockerClient, err := newDockerClient(dockerHost)
	if err != nil {
		die(err.Error())
	}

	dnsZone = make(map[string]net.IP, 0)
	containerListeners = make(map[string]*Listener)
	sourceAddrs = make(map[string]map[int]*net.TCPAddr)

	go startDns()
	go startAPI()

	dockerEvents := make(chan *docker.APIEvents)
	err = dockerClient.AddEventListener(dockerEvents)
	if err != nil {
		die(err.Error())
	}

	containers, err := dockerClient.ListContainers(docker.ListContainersOptions{})
	if err != nil {
		die(err.Error())
	}

	for _, c := range containers {
		addContainer(dockerClient, c.ID)
	}

	for ev := range dockerEvents {
		switch ev.Status {
		case "start":
			addContainer(dockerClient, ev.ID)
		case "stop":
			removeContainer(ev.ID)
		}
	}
}

func succIP(ip net.IP) net.IP {
	if ip.To4() == nil {
		panic("only IPv4 supported at the moment")
	}
	ipInt := (uint32(ip[12]) << 24) | (uint32(ip[13]) << 16) |
		(uint32(ip[14]) << 8) | uint32(ip[15])
	ipInt += 1
	return net.IP([]byte{
		byte(ipInt >> 24),
		byte(ipInt >> 16),
		byte(ipInt >> 8),
		byte(ipInt),
	})
}

func sourceAddrForPort(port int, dest *net.TCPAddr) *net.TCPAddr {
	getSourceAddr := func(addr string) *net.TCPAddr {
		src, err := net.ResolveTCPAddr("tcp",
			fmt.Sprintf("%s:%d", addr, port))
		if err != nil {
			panic(err)
		}
		return src
	}

	var lastAddr string
	for addr, ls := range sourceAddrs {
		lastAddr = addr
		if _, ok := ls[port]; !ok {
			ls[port] = dest
			return getSourceAddr(addr)
		}
	}

	var nextIP net.IP
	if lastAddr == "" {
		nextIP = SourceStartIP
	} else {
		lastAddrIP := net.ParseIP(lastAddr)
		if lastAddrIP == nil {
			panic("lastAddr not an IP address")
		}
		nextIP = succIP(lastAddrIP)
	}

	if !nextIP.IsLoopback() {
		panic("ran out of loopback addresses!")
	}

	addr := nextIP.String()
	ifconfig := exec.Command("ifconfig", "lo0", "alias", addr, "up")
	if err := ifconfig.Run(); err != nil {
		panic(fmt.Sprintf(
			"error calling ifconfig, adding alias for %s: %s",
			addr, err))
	}

	sourceAddrs[addr] = map[int]*net.TCPAddr{
		port: dest,
	}
	return getSourceAddr(addr)
}

var dnsNameAllowedChars = regexp.MustCompile(`[^-a-z0-9]+`)
var dnsNameHyphenStrings = regexp.MustCompile(`-{2,}`)

func dnsNameFromContainerName(containerName string) string {
	return dnsNameHyphenStrings.ReplaceAllLiteralString(
		strings.Trim(dnsNameAllowedChars.ReplaceAllLiteralString(
			containerName, "-"), "-"), "-")
}

func ListenerFromContainerAndPort(container *docker.Container, port docker.APIPort) (out *Listener, err error) {

	if container.Name == "" {
		return nil, fmt.Errorf("Container %s has no name from which to build a DNS name", container.ID)
	}

	if port.PublicPort == 0 || port.PrivatePort == 0 {
		return nil, fmt.Errorf("Public port not exposed for %d on %s",
			port.PublicPort, container.Name)
	}

	out = &Listener{
		finished:      &sync.WaitGroup{},
		newConn:       make(chan net.Conn),
		closedConn:    make(chan net.Conn),
		closeAllConns: make(chan struct{}),
	}

	out.DNSName = dnsNameFromContainerName(container.Name)
	if out.DNSName == "" {
		return nil, fmt.Errorf("Couldn't build a non-empty DNS name from '%s'", container.Name)
	}

	destIPAddr, err := net.ResolveIPAddr("ip", port.IP)
	if err != nil {
		return
	}
	out.Dest = new(net.TCPAddr)
	if destIPAddr.IP.IsUnspecified() {
		out.Dest.IP = dockerIP
	} else {
		out.Dest.IP = destIPAddr.IP
	}
	out.Dest.Port = int(port.PublicPort)
	out.Dest.Zone = destIPAddr.Zone
	out.Src = sourceAddrForPort(int(port.PrivatePort), out.Dest)
	return
}

func (self *Listener) Start() {
	log.Printf("Started listener on %s; listening: %v; dialling: %v", self.DNSName, *self.Src, *self.Dest)
	var err error
	self.tcpListener, err = net.ListenTCP("tcp", self.Src)
	if err != nil {
		panic(err)
	}

	self.finished.Add(1)

	go func() {
		openConnections := make(map[net.Conn]bool)
		for {
			select {
			case conn := <-self.newConn:
				openConnections[conn] = true
			case conn := <-self.closedConn:
				delete(openConnections, conn)
			case _ = <-self.closeAllConns:
				for conn, _ := range openConnections {
					conn.Close()
				}
				self.finished.Done()
				return
			}
		}
	}()

	go func() {
		for {
			conn, err := self.tcpListener.Accept()
			if err != nil {
				log.Printf("Shutting down listener on %s", self.DNSName)
				self.closeAllConns <- struct{}{}
				return
			}

			self.newConn <- conn

			go self.forward(conn)
		}
	}()
}

func (self *Listener) Stop() {
	if self.tcpListener != nil {
		log.Printf("Stopping listener on %s", self.DNSName)
		self.tcpListener.Close()
		self.closeAllConns <- struct{}{}
	}
}

func (self *Listener) Wait() {
	self.finished.Wait()
}

func (self *Listener) forward(local net.Conn) {
	remote, err := net.DialTCP("tcp", nil, self.Dest)
	if err != nil {
		log.Printf("Remote dial failed: %v\n", err)
		return
	}
	wg := sync.WaitGroup{}

	self.finished.Add(2)
	wg.Add(2)

	go func() {
		io.Copy(local, remote)
		self.finished.Done()
		wg.Done()
	}()
	go func() {
		io.Copy(remote, local)
		self.finished.Done()
		wg.Done()
	}()

	wg.Wait()
	self.closedConn <- local
}
