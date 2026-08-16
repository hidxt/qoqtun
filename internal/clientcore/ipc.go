package clientcore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Local IPC: the running client exposes a 127.0.0.1 TCP endpoint so the
// `client tunnel ...` commands can control the live process. It is NOT a
// remote management channel: loopback only, guarded by a CSPRNG token that
// is written (0600) next to the state file. V1 trust model: local user.
type IPC struct {
	Client *Client
	Log    *slog.Logger

	ln   net.Listener
	port int
	tok  string
	once sync.Once
}

// NewIPC starts the loopback control endpoint and returns its port+token.
func NewIPC(c *Client, log *slog.Logger) (*IPC, error) {
	tokBytes := make([]byte, 16)
	if _, err := rand.Read(tokBytes); err != nil {
		return nil, fmt.Errorf("ipc: generate token: %w", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("ipc: listen: %w", err)
	}
	ipc := &IPC{
		Client: c,
		Log:    log,
		ln:     ln,
		port:   ln.Addr().(*net.TCPAddr).Port,
		tok:    hex.EncodeToString(tokBytes),
	}
	go ipc.serve()
	return ipc, nil
}

// Port returns the bound loopback port.
func (ipc *IPC) Port() int { return ipc.port }

// Token returns the loopback auth token.
func (ipc *IPC) Token() string { return ipc.tok }

// Close stops the endpoint.
func (ipc *IPC) Close() {
	ipc.once.Do(func() { _ = ipc.ln.Close() })
}

func (ipc *IPC) serve() {
	for {
		conn, err := ipc.ln.Accept()
		if err != nil {
			return
		}
		go ipc.handle(conn)
	}
}

// ipcReq is the request envelope from `client tunnel ...`.
type ipcReq struct {
	Token string          `json:"token"`
	Cmd   string          `json:"cmd"` // list|start|stop|status
	Name  string          `json:"name,omitempty"`
	Type  string          `json:"type,omitempty"`
	Args  json.RawMessage `json:"args,omitempty"`
}

// ipcResp is the response envelope.
type ipcResp struct {
	OK   bool   `json:"ok"`
	Err  string `json:"error,omitempty"`
	Data any    `json:"data,omitempty"`
}

func (ipc *IPC) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var req ipcReq
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		writeIPCResp(conn, ipcResp{OK: false, Err: "bad request"})
		return
	}
	if req.Token != ipc.tok {
		writeIPCResp(conn, ipcResp{OK: false, Err: "forbidden"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	switch req.Cmd {
	case "list":
		writeIPCResp(conn, ipcResp{OK: true, Data: ipc.Client.TunnelList()})
	case "status":
		writeIPCResp(conn, ipcResp{OK: true, Data: ipc.Client.Status()})
	case "start":
		if req.Type == "" {
			req.Type = "tcp"
		}
		spec := TunnelSpec{Name: req.Name, Type: req.Type, Enabled: true}
		if len(req.Args) > 0 {
			var a struct {
				RemotePort int    `json:"remote_port"`
				LocalIP    string `json:"local_ip"`
				LocalPort  int    `json:"local_port"`
				HTTPHost   string `json:"http_host"`
			}
			if err := json.Unmarshal(req.Args, &a); err != nil {
				writeIPCResp(conn, ipcResp{OK: false, Err: "bad args"})
				return
			}
			spec.RemotePort, spec.LocalIP, spec.LocalPort, spec.HTTPHost = a.RemotePort, a.LocalIP, a.LocalPort, a.HTTPHost
		}
		if err := ipc.Client.RegisterTunnel(ctx, spec); err != nil {
			writeIPCResp(conn, ipcResp{OK: false, Err: err.Error()})
			return
		}
		writeIPCResp(conn, ipcResp{OK: true})
	case "stop":
		if err := ipc.Client.UnregisterTunnel(ctx, req.Name); err != nil {
			writeIPCResp(conn, ipcResp{OK: false, Err: err.Error()})
			return
		}
		writeIPCResp(conn, ipcResp{OK: true})
	default:
		writeIPCResp(conn, ipcResp{OK: false, Err: "unknown cmd"})
	}
}

func writeIPCResp(conn net.Conn, r ipcResp) {
	_ = json.NewEncoder(conn).Encode(r)
}
