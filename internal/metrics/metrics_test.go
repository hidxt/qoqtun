package metrics

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCounters(t *testing.T) {
	r := NewRegistry()
	r.ConnOpened("c1", "t1")
	r.ConnOpened("c1", "t1")
	r.RecordConn("c1", "t1", 100, 50)
	r.RecordConn("c1", "t1", 200, 25)

	snap := r.Snapshot()
	if snap.GlobalRxBytes != 300 || snap.GlobalTxBytes != 75 {
		t.Fatalf("global rx/tx = %d/%d, want 300/75", snap.GlobalRxBytes, snap.GlobalTxBytes)
	}
	if len(snap.Clients) != 1 {
		t.Fatalf("clients = %d, want 1", len(snap.Clients))
	}
	cs := snap.Clients[0]
	if cs.ClientID != "c1" || cs.TotalConns != 2 || cs.ActiveConns != 0 {
		t.Fatalf("client stats wrong: %+v", cs)
	}
	if len(cs.Tunnels) != 1 || cs.Tunnels[0].RxBytes != 300 {
		t.Fatalf("tunnel stats wrong: %+v", cs.Tunnels)
	}
}

func TestConcurrentCounters(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				r.ConnOpened("c1", "t1")
				r.RecordConn("c1", "t1", 1, 1)
			}
		}()
	}
	wg.Wait()
	snap := r.Snapshot()
	if snap.GlobalRxBytes != 8000 || snap.GlobalConns != 8000 {
		t.Fatalf("counters lost updates: rx=%d conns=%d, want 8000/8000",
			snap.GlobalRxBytes, snap.GlobalConns)
	}
}

func TestSnapshotConsistency(t *testing.T) {
	r := NewRegistry()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			r.RecordConn("c1", "t1", 1, 1)
			r.RecordUDP("c1", "t2", 1, 0)
		}
	}()
	for i := 0; i < 1000; i++ {
		snap := r.Snapshot() // must never tear or race
		_ = snap.GlobalRxBytes
		for _, c := range snap.Clients {
			_ = c.RxBytes
			for _, tn := range c.Tunnels {
				_ = tn.RxBytes
			}
		}
	}
	done <- struct{}{}
	<-done
}

func TestRateWindow(t *testing.T) {
	w := NewRateWindow()
	w.Add(1000)
	perSec, avg := w.Rate()
	if perSec != 1000 || avg != 1000/60 {
		t.Fatalf("rate = %d/%d, want 1000/16", perSec, avg)
	}
	// advance time by crediting across a boundary
	for i := 0; i < 5; i++ {
		time.Sleep(1100 * time.Millisecond)
		w.Add(500)
	}
	perSec, _ = w.Rate()
	if perSec != 500 {
		t.Fatalf("instantaneous rate = %d, want 500", perSec)
	}
}

func TestUDPStats(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 7; i++ {
		r.RecordUDP("c1", "u1", 1, 0)
	}
	for i := 0; i < 3; i++ {
		r.RecordUDP("c1", "u1", 0, 1)
	}
	snap := r.Snapshot()
	if snap.Clients[0].Tunnels[0].UDPRxPackets != 7 || snap.Clients[0].Tunnels[0].UDPTxPackets != 3 {
		t.Fatalf("udp stats wrong: %+v", snap.Clients[0].Tunnels[0])
	}
}

func TestRemoveClient(t *testing.T) {
	r := NewRegistry()
	r.ConnOpened("gone", "t")
	r.RemoveClient("gone")
	if n := len(r.Snapshot().Clients); n != 0 {
		t.Fatalf("clients after remove = %d", n)
	}
}

var _ = fmt.Sprintf
