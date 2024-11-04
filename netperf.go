package main

import (
	"bufio"
	"container/list"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	//"reflect"
	"strconv"
	"strings"
	"time"
)

/*
TODO:
1. tcp server/client: done
2. udp server/client: done
3. file transfer
4. use netperf header or only send/receive specific len of data
5. interval of sending data needs to change as dynamic value
*/

const VERSION = "2.0"

var (
	version = flag.Bool("v", false, "Print netperf version")
	server  = flag.Bool("s", false, "Run in server mode")
	client  = flag.String("c", "", "-c <host>\n\t Run in client mode, connect to <host>")
	port    = flag.String("p", "6500", "Server port to listen on or connect to")
	udp     = flag.Bool("u", false, "Use udp protocol")
	//transTime = flag.Int("t", 10, "Transmission time")
	sendInterval = flag.Int("t", 1000, "Time to send data, in millisecond")
	interval     = flag.Float64("i", 5, "Seconds to report bandwidth")
	bufSize      = flag.Int("b", 8192, "Receive buffer size")
	dataLen      = flag.Int("l", 256, "Transmission data length")
	//fileServ     = flag.Bool("fs", false, "Start as file server")
	transFile = flag.String("f", "", "Transmission file")
)

const (
	/* Run mode */
	MODE_SERVER      = 0x1
	MODE_CLIENT      = 0x2
	MODE_FILE_SERVER = 0x4
	MODE_FILE_CLIENT = 0x8
	MODE_MASK        = 0xFF

	/* Protocol */
	PROTO_TCP = 6
	PROTO_UDP = 17

	/* Header */
	NETPERF_TOKEN = "NETPERF"

	/* Buffer for file transfer */
	BUFFER_SIZE = 1024
)

/* Client: Record client reading rate */
type NetPerfClientStat struct {
	readRate float64 //per packet/s
	readSize int
	dataRate float64 //per Byte/s
	count    int
	total    int
}

/* Server: Record server sending rate */
type NetPerfServerStat struct {
	sendRate float64
	sendSize int
	dataRate float64
	count    int
	total    int
}

/* Client/Server: Execute flag */
type NetPerf struct {
	mode    int
	proto   int
	bufSize int
	len     int
	port    string
	addr    string
}

/* Server: Record client information for server */
type NetPerfClient struct {
	//cStat NetPerfServerStat
	addr string
	conn net.Conn
}

/* Server: Maintain client list, sending rate for each client and global statistic */
type NetPerfServer struct {
	clientList *list.List        /* client list */
	gStat      NetPerfServerStat /* global statistic */
	//ServerToClientStatList map[NetPerfClient]NetPerfServerStat
}

var (
	mode     int               /* 0: server mode, 1: client mode */
	proto    int               /* connection protocol */
	isClient bool              /* Server: is there any connection established */
	netperf  NetPerf           /* save execute flag */
	npServer NetPerfServer     /* netperf server */
	npClient NetPerfClientStat /* netperf client statistic */
	isToken  bool              /* udp server for keep connection */
)

func GetVersion() {
	fmt.Printf("netperf version - %s\n", VERSION)
}

func MemSet(a []byte, v byte) {
	for i := range a {
		a[i] = v
	}
}

func CheckRunMode() {

	if *server {
		if strings.Compare(*client, "") != 0 {
			log.Printf("Mode conflict, please set server or client mode only")
			os.Exit(0)
		}
		if strings.Compare(*transFile, "") != 0 {
			mode = MODE_FILE_SERVER
			return
		}
		mode = MODE_SERVER

	} else {
		if strings.Compare(*client, "") != 0 {
			if strings.Compare(*transFile, "get") == 0 {
				mode = MODE_FILE_CLIENT
			} else {
				mode = MODE_CLIENT
			}
		}
	}
	log.Printf("Run mode:%d", mode)
}

func CheckProto() {
	if *udp {
		proto = PROTO_UDP
	} else {
		proto = PROTO_TCP
	}
}

func (np *NetPerf) NetPerfInit() {
	np.mode = mode
	np.proto = proto
	np.len = *dataLen
	np.bufSize = *bufSize
	np.port = *port
	np.addr = *client
}

func BuildNetPerfHeader() {

}

func GenerateData(dLen int) []byte {
	seeds := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]byte, dLen)
	for i := range b {
		b[i] = seeds[rand.Intn(len(seeds))]
	}
	return b
}

func (np *NetPerf) HandleTCPClient() {
	log.Printf("Handle TCP client")
	buf := make([]byte, np.len)
	for {
		buf = GenerateData(np.len)
		for e := npServer.clientList.Front(); e != nil; e = e.Next() {
			element := e.Value.(NetPerfClient)

			/* Write data to clients */
			l, err := element.conn.Write(buf)
			if err != nil {
				log.Printf("Write data to client:%s fail.", element.conn.RemoteAddr().String())
				/* Remove client info from client list */
				npServer.clientList.Remove(e)
				if npServer.clientList.Len() == 0 {
					isClient = false
				}
			}

			/* client count/total increasing and global count/total increasing  */

			npServer.gStat.count++
			npServer.gStat.total++

			//if *debug {
			log.Printf("Wrtie len:%d, count:%d, total:%d", l, npServer.gStat.count, npServer.gStat.total)
			//log.Printf("Wrtie len:%d, count:%d, total:%d, c_count:%d, c_total:%d", l, npServer.gStat.count, npServer.gStat.total, e.Value.(NetPerfClient).cStat.count, e.Value.(NetPerfClient).cStat.total)
			//}
		}
		//time.Sleep(1 * time.Second)
		time.Sleep(time.Duration(*sendInterval) * time.Millisecond)
	} // end of for loop
}

func (np *NetPerf) StartTCPServer() {
	log.Printf("Start TCP server")
	/* NetPerfServer struct init */
	npServer.clientList = list.New()
	s, err := net.Listen("tcp", ":"+np.port)
	if err != nil {
		log.Printf("Listen socket failed...%v", err)
	}
	defer s.Close()

	/* netperf info record per client */
	npClient := NetPerfClient{}
	/*
		npClient := NetPerfClient{
			cStat: NetPerfServerStat{
				sendRate: 0.0,
				sendSize: 0,
				dataRate: 0.0,
				count:    0,
				total:    0,
			},
		}
	*/
	for {
		conn, err := s.Accept()
		if err != nil {
			log.Printf("Accept connection fail...%v", err)
			continue // Keep server alive
		}

		npClient.conn = conn
		npClient.addr = conn.RemoteAddr().String()

		/* Add client to list */
		npServer.clientList.PushBack(npClient)
		log.Printf("%s, num of client:%d", npClient.addr, npServer.clientList.Len())

		/* TODO: add flag check send from the same routine or new another routine */
		if !isClient {
			isClient = true
			go np.HandleTCPClient()
		} else {
			log.Printf("Already start to send data")
		}
	}

}

/* TODO: With netperf header / Without netperf header */
func (np *NetPerf) TCPDataReceiver(d chan []byte) {
	readLen := 0
	index := 0

	data := make([]byte, netperf.len)
	readLen = netperf.len
	// add copy to data for make sure data is correct
	for {
		if readLen < netperf.len {
			pipe := <-d
			remainIndex := readLen
			copy(data[index:index+readLen], pipe[0:remainIndex])
			//fmt.Println("COPY remain, readLen:", readLen, "remainIndex", remainIndex, "index:", index, "len(pipe):", len(pipe))

			readLen = readLen - remainIndex
			index = index + remainIndex

			if readLen == 0 {
				readLen = netperf.len
				index = 0
				npClient.count++
				npClient.total++
				MemSet(data, 0)
			}

			remainLen := len(pipe) - remainIndex
			loop := remainLen / netperf.len
			newRemain := remainLen % netperf.len
			lastPtr := 0

			for i := 0; i < loop; i++ {
				copy(data[0:netperf.len], pipe[i*(netperf.len)+remainIndex:i*(netperf.len)+netperf.len+remainIndex])
				npClient.count++
				npClient.total++
				lastPtr = i*(netperf.len) + netperf.len + remainIndex // = (i+1) * dataLen + remainIndex
			}
			if newRemain > 0 {
				copy(data[index:index+newRemain], pipe[lastPtr:lastPtr+newRemain])
				readLen = readLen - newRemain
				index = index + newRemain
			}

		} else {
			pipe := <-d
			loop := len(pipe) / netperf.len
			remain := len(pipe) % netperf.len
			lastPtr := 0 // if loop == 0 and remain > 0, start from index 0
			//			fmt.Println("DOWN handle data, loop:", loop, "remain:", remain)
			for i := 0; i < loop; i++ {
				copy(data[0:netperf.len], pipe[i*(netperf.len):i*(netperf.len)+netperf.len])
				lastPtr = i*(netperf.len) + netperf.len // = (i+1) * dataLen
				npClient.count++
				npClient.total++
				//reset data buffer
				MemSet(data, 0)
			}
			if remain > 0 {
				copy(data[index:index+remain], pipe[lastPtr:lastPtr+remain])
				readLen = readLen - remain //already read minux
				index = index + remain
			}
		}
	}
}

func (np *NetPerf) WriteDataToUDPClient(conn *net.UDPConn, remote *net.UDPAddr) {
	for {
		data := GenerateData(np.len)
		n, err := conn.WriteToUDP(data, remote)
		if err != nil {
			log.Printf("Write data fail...%v", err)
			isClient = false
			conn.Close()
			return
		}

		npServer.gStat.count++
		npServer.gStat.total++
		log.Printf("Write %d bytes data to remote:%s", n, remote.String())
		time.Sleep(time.Duration(*sendInterval) * time.Millisecond)
	}
}

/* Server: handle udp client */
//func (np *NetPerf) HandleUDPClient(conn *net.UDPConn, remote *net.UDPAddr) {
func (np *NetPerf) HandleUDPClient(conn *net.UDPConn) {
	log.Printf("Handle UDP client")

	/* new design start */

	buffer := make([]byte, len(NETPERF_TOKEN))
	n, addr, err := conn.ReadFromUDP(buffer)
	log.Printf("Read %d bytes from client", n)
	if err != nil {
		log.Printf("Read from client fail...%v", err)
		conn.Close()
		return
	}
	if strings.Compare(string(buffer), NETPERF_TOKEN) != 0 {
		log.Printf("Token is not \"NETPERF\"")
		conn.Close()
		return
	}

	isClient = true
	go np.WriteDataToUDPClient(conn, addr)

	/* new design end */

}

func (np *NetPerf) StartUDPServer() {
	log.Printf("Start UDP server")
	/* new design start */

	addr, err := net.ResolveUDPAddr("udp", ":"+np.port)
	if err != nil {
		log.Printf("Resolve udp addr fail...%v", err)
		os.Exit(1)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("Listen UDP socket fail...%v", err)
		os.Exit(1)
	}
	defer conn.Close()

	log.Printf("Listen on udp socket.")

	for {
		np.HandleUDPClient(conn)
	}

	/* new design end */
}

func (np *NetPerf) StartTCPClient() {
	log.Printf("Start TCP client")

	conn, err := net.Dial("tcp", np.addr+":"+np.port)
	if err != nil {
		log.Printf("Establish connection fail...%v", err)
	}
	defer conn.Close()

	msg := make([]byte, np.bufSize)
	c := make(chan []byte, 1)

	go np.TCPDataReceiver(c)

	for {
		size, err := bufio.NewReader(conn).Read(msg)

		switch err {
		case io.EOF:
			log.Printf("Read io.EOF, break read loop")
			os.Exit(1)
		case nil:
			data := make([]byte, size)
			copy(data[0:size], msg[0:size])
			c <- data
		default:
			log.Printf("Receive data fail...%v", err)
			os.Exit(1)

		}
	}
}

func (np *NetPerf) StartUDPClient() {
	log.Printf("Start UDP client")
	addr, err := net.ResolveUDPAddr("udp", np.addr+":"+np.port)
	if err != nil {
		log.Printf("Resolve udp addr fail...%v", err)
		os.Exit(1)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf("Dial up udp fail...%v", err)
	}
	defer conn.Close()

	token := []byte("NETPERF")
	n, err := conn.Write(token)
	if err != nil {
		log.Printf("Write token fail...%v", err)
		os.Exit(1)
	}
	log.Printf("Write token %d bytes done.", n)

	/* new design start */
	for {
		buffer := make([]byte, np.len)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Read from server fail...%v", err)
			os.Exit(1)
		}

		npClient.count++
		npClient.total++
		log.Printf("Receive from UDP client %d bytes.", n)
	}
	/* new design end */
}

func (np *NetPerf) SendFile(conn net.Conn) {
	log.Printf("Send file to client")
	defer conn.Close()

	file, err := os.Open(*transFile)
	if err != nil {
		log.Printf("Open file failed...%v", err)
		os.Exit(1)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Get file info failed...%v", err)
	}

	size := fileInfo.Size()
	name := fileInfo.Name()

	log.Printf("file name:%s, file size:%d,%s", name, size, strconv.FormatInt(size, 10))
	//	CreateHeader(name, size)

	//conn.Write([]byte(NETPERF_TOKEN))
	//time.Sleep(5 * time.Second)
	/*
		fsize := make([]byte, 16)
		fsize = []byte(strconv.FormatInt(size, 10))
		log.Printf("size:%v", fsize)
		conn.Write(fsize)
		//time.Sleep(5 * time.Second)
		fname := make([]byte, 256)
		fname = []byte(name)
		log.Printf("name:%v", fname)
		conn.Write(fname)
	*/

	fileSize := fillString(strconv.FormatInt(size, 10), 16)
	fileName := fillString(name, 128)
	conn.Write([]byte(fileSize))
	conn.Write([]byte(fileName))

	buffer := make([]byte, BUFFER_SIZE)
	for {
		_, err := file.Read(buffer)
		if err == io.EOF {
			break
		}
		conn.Write(buffer)
	}
	log.Printf("File sent finished.")
	return
}

func fillString(retunString string, toLength int) string {
	for {
		lengtString := len(retunString)
		if lengtString < toLength {
			retunString = retunString + ":"
			continue
		}
		break
	}
	return retunString
}

func (np *NetPerf) StartFileServer() {
	log.Printf("Start file server")

	s, err := net.Listen("tcp", ":"+np.port)
	if err != nil {
		log.Printf("File server listen socket failed...%v", err)
	}
	defer s.Close()

	for {
		conn, err := s.Accept()
		if err != nil {
			log.Printf("File server accept failed...%v", err)
			os.Exit(1)
		}
		go np.SendFile(conn)
	}
}

func (np *NetPerf) StartFileClient() {
	log.Printf("Start file client")

	conn, err := net.Dial("tcp", np.addr+":"+np.port)
	if err != nil {
		log.Printf("Establish connection fail...%v", err)
	}
	defer conn.Close()

	/*
		token := make([]byte, 7)
		_, err = bufio.NewReader(conn).Read(token)

		log.Printf("Token:%s", string(token))
		if strings.Compare(string(token), NETPERF_TOKEN) != 0 {
			log.Printf("Token does not match...token:%s,%v", token, err)
			os.Exit(1)
		}
	*/

	fsizeBuf := make([]byte, 16)
	conn.Read(fsizeBuf)
	fsize, _ := strconv.ParseInt(strings.Trim(string(fsizeBuf), ":"), 10, 64)
	log.Printf("Read file size:%d", fsize)

	fnameBuf := make([]byte, 128)
	conn.Read(fnameBuf)
	fname := strings.Trim(string(fnameBuf), ":")

	file, err := os.Create(fname)
	if err != nil {
		log.Printf("Create new file %s failed...%v", fname, err)
		os.Exit(1)
	}
	defer file.Close()

	var recvSize int64
	for {
		if (fsize - recvSize) < BUFFER_SIZE {
			io.CopyN(file, conn, (fsize - recvSize))
			_, err = conn.Read(make([]byte, (recvSize+BUFFER_SIZE)-fsize))
			if err == io.EOF {
				break
			} else if err != nil {
				log.Printf("Receiving file failed...%v", err)
				os.Exit(1)
			}
		}
		io.CopyN(file, conn, BUFFER_SIZE)
		recvSize += BUFFER_SIZE
	}
	log.Printf("Receive file completely")
	os.Exit(0)
}

func (np *NetPerf) StartUDPBroadcast() {
	log.Printf("Start UDP broadcast")
}

func (np *NetPerf) StartServer() {
	log.Printf("Start server")
	switch np.proto {
	case PROTO_TCP:
		go np.StartTCPServer()
	case PROTO_UDP:
		go np.StartUDPServer()
	}
}

func (np *NetPerf) StartClient() {
	log.Printf("Start client")
	switch np.proto {
	case PROTO_TCP:
		go np.StartTCPClient()
	case PROTO_UDP:
		go np.StartUDPClient()
	}
}

func DataRateReport() {
	/* TODO: support millisecond sleep */
	for {
		if netperf.mode == MODE_CLIENT {
			npClient.readRate = float64(npClient.count) / *interval
			if *udp {
				npClient.dataRate = float64(npClient.count*netperf.len) / *interval
			} else {
				npClient.dataRate = float64(npClient.count*netperf.len) / *interval
			}
			log.Printf("Data rate:%v f/s, data rate:%v Bytes/s, count:%d, total:%d", npClient.readRate, npClient.dataRate, npClient.count, npClient.total)
			npClient.count = 0
		} else if netperf.mode == MODE_SERVER {
			if isClient && !*udp {
				npServer.gStat.sendRate = float64(npServer.gStat.count) / *interval
				npServer.gStat.dataRate = float64(npServer.gStat.count*netperf.len) / *interval
				log.Printf("Sending rate:%v f/s, data rate:%v Bytes/s, count:%d, tatol:%d", npServer.gStat.sendRate, npServer.gStat.dataRate, npServer.gStat.count, npServer.gStat.total)
				npServer.gStat.count = 0
				/*
					log.Printf("====================================================================================")
					for e := npServer.clientList.Front(); e != nil; e = e.Next() {
						element := e.Value.(NetPerfClient)
						//npServer.clientList.Remove(e)
						element.cStat.sendRate = float64(element.cStat.count) / *interval
						element.cStat.dataRate = float64(element.cStat.count*netperf.len) / *interval
						log.Printf("Conn:%s, Sending rate:%v f/s, data rate:%v Bytes/s, count:%d, total:%d", element.addr, element.cStat.sendRate, element.cStat.dataRate, element.cStat.count, element.cStat.total)
						element.cStat.count = 0
						//npServer.clientList.PushBack(element)
					}
					log.Printf("====================================================================================")
				*/
			} else if isClient && *udp {
				npServer.gStat.sendRate = float64(npServer.gStat.count) / *interval
				npServer.gStat.dataRate = float64(npServer.gStat.count*netperf.len) / *interval
				log.Printf("Sending rate:%v f/s, data rate:%v Bytes/s, count:%d, total:%d", npServer.gStat.sendRate, npServer.gStat.dataRate, npServer.gStat.count, npServer.gStat.total)
				npServer.gStat.count = 0
				npClient.count = 0
			} else {
				/* No establish connection, re-init global count */
				npServer.gStat.count = 0
				npServer.gStat.total = 0
			}

		}
		time.Sleep(time.Duration(*interval) * 1000 * time.Millisecond)
	}
}

func main() {
	flag.Parse()

	if *version {
		GetVersion()
		os.Exit(0)
	}

	CheckRunMode()
	CheckProto()

	//netperf := NetPerf{}
	netperf.NetPerfInit()

	log.Printf("mode:%d, proto:%d, len:%d, bufSize:%d, port:%s", netperf.mode, netperf.proto, netperf.len, netperf.bufSize, netperf.port)
	isClient = false
	switch netperf.mode {
	case MODE_SERVER:
		netperf.StartServer()
	case MODE_CLIENT:
		netperf.StartClient()
	case MODE_FILE_SERVER:
		netperf.StartFileServer()
	case MODE_FILE_CLIENT:
		netperf.StartFileClient()

	}

	DataRateReport()
}
