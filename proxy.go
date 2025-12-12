package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/gogoods/mysql-proxy/chat"
	"github.com/gogoods/mysql-proxy/conf"
	"github.com/gogoods/mysql-proxy/protocol"
)

type RequestPacketParser struct {
	connId        string
	queryId       *int
	queryChan     chan chat.Cmd
	connStateChan chan chat.ConnState
	timer         *time.Time
}

func (pp *RequestPacketParser) Write(p []byte) (n int, err error) {
	*pp.queryId++
	*pp.timer = time.Now()

	switch protocol.GetPacketType(p) {
	case protocol.ComStmtPrepare:
	case protocol.ComQuery:
		decoded, err := protocol.DecodeQueryRequest(p)
		if err == nil {
			pp.queryChan <- chat.Cmd{pp.connId, *pp.queryId, "", decoded.Query, nil, false}
		}
	case protocol.ComQuit:
		pp.connStateChan <- chat.ConnState{pp.connId, protocol.ConnStateFinished}
	}

	return len(p), nil
}

type ResponsePacketParser struct {
	connId          string
	queryId         *int
	queryResultChan chan chat.CmdResult
	timer           *time.Time
}

func (pp *ResponsePacketParser) Write(p []byte) (n int, err error) {
	duration := fmt.Sprintf("%.3f", time.Since(*pp.timer).Seconds())

	switch protocol.GetPacketType(p) {
	case protocol.ResponseErr:
		decoded, _ := protocol.DecodeErrResponse(p)
		pp.queryResultChan <- chat.CmdResult{pp.connId, *pp.queryId, protocol.ResponseErr, decoded, duration}
	default:
		pp.queryResultChan <- chat.CmdResult{pp.connId, *pp.queryId, protocol.ResponseOk, "", duration}
	}

	return len(p), nil
}

// MySQLProxyServer implements server for capturing and forwarding MySQL traffic.
type MySQLProxyServer struct {
	cmdChan       chan chat.Cmd
	cmdResultChan chan chat.CmdResult
	connStateChan chan chat.ConnState
	appReadyChan  chan bool
	mysqlHost     string
	proxyHost     string
	proxyPasswd   string
}

// run starts accepting TCP connection and forwarding it to MySQL server.
// Each incoming TCP connection is handled in own goroutine.
func (p *MySQLProxyServer) run() {
	listener, err := net.Listen("tcp", p.proxyHost)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer listener.Close()

	go func() {
		p.appReadyChan <- true
		close(p.appReadyChan)
	}()

	for {
		client, err := listener.Accept()
		if err != nil {
			log.Print(err.Error())
		}

		go p.handleConnection(client)
	}
}

// handleConnection ...
func (p *MySQLProxyServer) handleConnection(client net.Conn) {
	defer client.Close()

	// IP白名单检查
	clientIP := client.RemoteAddr().(*net.TCPAddr).IP.String()
	//log.Printf("Connection from IP %s ", clientIP)
	allowIps := conf.Config().AllowIps
	if len(allowIps) > 0 {
		allowed := false
		for _, ip := range allowIps {
			if ip == clientIP {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Printf("Connection from IP %s is not allowed", clientIP)
			return
		}
	}

	// New connection to MySQL is made per each incoming TCP request to MySQLProxyServer server.
	server, err := net.Dial("tcp", p.mysqlHost)
	if err != nil {
		log.Print(err.Error())
		return
	}
	defer server.Close()

	// 如果配置了代理密码，需要验证客户端密码
	if p.proxyPasswd != "" {
		// 1. 从MySQL服务器读取初始握手包
		buffer := make([]byte, 1024)
		n, err := server.Read(buffer)
		if err != nil {
			log.Printf("Failed to read handshake packet: %v", err)
			return
		}
		handshakePacket := buffer[:n]

		// 2. 将握手包发送给客户端
		if _, err := client.Write(handshakePacket); err != nil {
			log.Printf("Failed to send handshake packet: %v", err)
			return
		}

		// 3. 从客户端读取握手响应包
		n, err = client.Read(buffer)
		if err != nil {
			log.Printf("Failed to read handshake response: %v", err)
			return
		}
		responsePacket := buffer[:n]

		// 4. 简单的密码验证：检查响应包中是否包含代理密码
		// 注意：这是一个简化的实现，实际MySQL认证更复杂
		// 这里我们假设客户端会直接发送明文密码（仅用于演示）
		if !containsPassword(responsePacket, p.proxyPasswd) {
			log.Printf("Invalid password from client %s", clientIP)
			// 发送错误响应
			errPacket := []byte{0x07, 0x00, 0x00, 0x01, 0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0', 'A', 'c', 'c', 'e', 's', 's', ' ', 'd', 'e', 'n', 'i', 'e', 'd', ' ', 'f', 'o', 'r', ' ', 'u', 's', 'e', 'r'}
			client.Write(errPacket)
			return
		}
	}

	connId := fmt.Sprintf("%s => %s", client.RemoteAddr().String(), server.RemoteAddr().String())

	defer func() { p.connStateChan <- chat.ConnState{connId, protocol.ConnStateFinished} }()

	var queryId int
	var timer time.Time

	// Copy bytes from client to server and requestParser
	go io.Copy(io.MultiWriter(server, &RequestPacketParser{connId, &queryId, p.cmdChan, p.connStateChan, &timer}), client)

	// Copy bytes from server to client and responseParser
	io.Copy(io.MultiWriter(client, &ResponsePacketParser{connId, &queryId, p.cmdResultChan, &timer}), server)
}

// containsPassword 检查响应包中是否包含代理密码
// 注意：这是一个简化的实现，实际MySQL认证更复杂
func containsPassword(packet []byte, password string) bool {
	// 简单检查包中是否包含密码字符串
	return bytes.Contains(packet, []byte(password))
}
