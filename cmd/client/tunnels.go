package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// tunnel commands talk to the running client over the loopback control
// endpoint (port + token from the 0600 status file).

// loadIPCInfo reads the control endpoint address from the status file.
func loadIPCInfo(statePath string) (port int, token string, err error) {
	if statePath == "" {
		statePath = defaultStatePath()
	}
	data, err := os.ReadFile(statePath + ".status.json")
	if err != nil {
		return 0, "", fmt.Errorf("client not running (no status file): %w", err)
	}
	var st struct {
		IPC struct {
			Port  int    `json:"port"`
			Token string `json:"token"`
		} `json:"ipc"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return 0, "", fmt.Errorf("status file corrupt: %w", err)
	}
	if st.IPC.Port == 0 {
		return 0, "", fmt.Errorf("client control endpoint not available (older version?)")
	}
	return st.IPC.Port, st.IPC.Token, nil
}

// ipcCall sends one command to the running client and decodes the response.
func ipcCall(statePath, cmd, name string, args any) ([]byte, error) {
	port, token, err := loadIPCInfo(statePath)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		Token string `json:"token"`
		Cmd   string `json:"cmd"`
		Name  string `json:"name,omitempty"`
		Type  string `json:"type,omitempty"`
		Args  any    `json:"args,omitempty"`
	}{Token: token, Cmd: cmd, Name: name, Args: args})
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to client control endpoint: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(body); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(conn); err != nil {
		return nil, err
	}
	var resp struct {
		OK   bool            `json:"ok"`
		Err  string          `json:"error"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("%s", resp.Err)
	}
	return resp.Data, nil
}

// newTunnelCmd implements `client tunnel list|start|stop|status`.
func newTunnelCmd() *cobra.Command {
	var statePath string
	cmd := &cobra.Command{
		Use:   "tunnel",
		Short: "Manage tunnels of the running client (local control endpoint)",
		Long: "Manage tunnels of the running client.\n\n" +
			"The commands talk to `client run` over a 127.0.0.1 control endpoint\n" +
			"(port+token read from the 0600 status file). Start/stop apply at\n" +
			"runtime only: V1 config changes require a restart to persist.",
	}
	cmd.PersistentFlags().StringVar(&statePath, "state", "", "path to state.json")

	var listArgs struct {
		json bool
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List running tunnels",
		RunE: func(cmd *cobra.Command, _ []string) error {
			data, err := ipcCall(statePath, "list", "", nil)
			if err != nil {
				return err
			}
			var tunnels []struct {
				Name       string `json:"Name"`
				Type       string `json:"Type"`
				LocalIP    string `json:"LocalIP"`
				LocalPort  int    `json:"LocalPort"`
				RemotePort int    `json:"RemotePort"`
				TunnelID   string `json:"TunnelID"`
			}
			if err := json.Unmarshal(data, &tunnels); err != nil {
				return err
			}
			if listArgs.json {
				os.Stdout.Write(data)
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tTYPE\tLOCAL\tREMOTE\tTUNNEL_ID")
			for _, t := range tunnels {
				remote := fmt.Sprintf("%d", t.RemotePort)
				if t.RemotePort == 0 {
					remote = "vhost"
				}
				fmt.Fprintf(w, "%s\t%s\t%s:%d\t%s\t%s\n",
					t.Name, t.Type, t.LocalIP, t.LocalPort, remote, t.TunnelID)
			}
			return w.Flush()
		},
	}
	list.Flags().BoolVar(&listArgs.json, "json", false, "output as JSON")
	cmd.AddCommand(list)

	start := &cobra.Command{
		Use:   "start <name> --remote-port N --local IP:PORT [--type TYPE] [--http-host HOST]",
		Short: "Start a tunnel at runtime (not persisted)",
		Example: `  qoqtun-client tunnel start web --remote-port 22000 --local 127.0.0.1:8080
  qoqtun-client tunnel start site --type http --http-host a.example.com --local 127.0.0.1:8080`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			local := startArgs.local
			host, port, err := splitHostPort(local)
			if err != nil {
				return err
			}
			argsMap := map[string]any{
				"remote_port": startArgs.remotePort,
				"local_ip":    host,
				"local_port":  port,
				"http_host":   startArgs.httpHost,
			}
			if _, err := ipcCall(statePath, "start", args[0], argsMap); err != nil {
				return err
			}
			fmt.Printf("tunnel %q started\n", args[0])
			return nil
		},
	}
	start.Flags().StringVar(&startArgs.local, "local", "", "local target IP:PORT")
	start.Flags().IntVar(&startArgs.remotePort, "remote-port", 0, "public remote port (0 = vhost for http)")
	start.Flags().StringVar(&startArgs.httpHost, "http-host", "", "http vhost host")
	cmd.AddCommand(start)

	stop := &cobra.Command{
		Use:     "stop <name>",
		Short:   "Stop a tunnel at runtime",
		Example: "  qoqtun-client tunnel stop web",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := ipcCall(statePath, "stop", args[0], nil); err != nil {
				return err
			}
			fmt.Printf("tunnel %q stopped\n", args[0])
			return nil
		},
	}
	cmd.AddCommand(stop)

	status := &cobra.Command{
		Use:   "status",
		Short: "Show client statistics (local)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			data, err := ipcCall(statePath, "status", "", nil)
			if err != nil {
				return err
			}
			var out bytes.Buffer
			if err := json.Indent(&out, data, "", "  "); err != nil {
				return err
			}
			_, _ = out.WriteTo(os.Stdout)
			return nil
		},
	}
	cmd.AddCommand(status)
	return cmd
}

var startArgs struct {
	local      string
	remotePort int
	httpHost   string
}

// splitHostPort splits "IP:PORT" into parts (the local flag format).
func splitHostPort(s string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("local target must be IP:PORT: %w", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid local port %q", portStr)
	}
	return host, port, nil
}
