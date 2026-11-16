// klima – lokalne sterowanie klimatyzatorem Tuya (protokół 3.4) dla apki Dom.
// Konfiguracja: klima.json w katalogu roboczym. HTTP: GET /status, POST /set {"dps":{"1":true}}.
// Działa też pod prefiksem /klima (tailscale serve --set-path /klima).
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type config struct {
	IP      string `json:"ip"`
	ID      string `json:"id"`
	Key     string `json:"key"`
	Version string `json:"version"`
	Name    string `json:"name"`
}

const (
	cmdNegStart  = 3
	cmdNegResp   = 4
	cmdNegFinish = 5
	cmdControl   = 0x0d
	cmdStatus    = 8
	cmdHeartbeat = 9
	cmdQueryNew  = 0x10
)

var noHeader = map[uint32]bool{cmdQueryNew: true, cmdHeartbeat: true, cmdNegStart: true, cmdNegResp: true, cmdNegFinish: true, 0x12: true}

// ---------- AES-ECB / ramki 55AA ----------

func ecb(key, data []byte, enc bool) []byte {
	b, _ := aes.NewCipher(key)
	out := make([]byte, len(data))
	for i := 0; i+16 <= len(data); i += 16 {
		if enc {
			b.Encrypt(out[i:i+16], data[i:i+16])
		} else {
			b.Decrypt(out[i:i+16], data[i:i+16])
		}
	}
	return out
}
func pad(d []byte) []byte {
	n := 16 - len(d)%16
	return append(append([]byte{}, d...), bytes.Repeat([]byte{byte(n)}, n)...)
}
func unpad(d []byte) []byte {
	if len(d) == 0 {
		return d
	}
	n := int(d[len(d)-1])
	if n < 1 || n > 16 || n > len(d) {
		return d
	}
	return d[:len(d)-n]
}
func mac(key, data []byte) []byte { h := hmac.New(sha256.New, key); h.Write(data); return h.Sum(nil) }

type dev struct {
	cfg  config
	mu   sync.Mutex // stan
	wmu  sync.Mutex // zapis do gniazda
	conn net.Conn
	key  []byte // klucz sesji
	seq  uint32
	dps  map[string]any
	at   time.Time
	err  string
	resp chan uint32 // odebrane komendy (do czekania na odpowiedź)
}

func (d *dev) send(cmd uint32, payload []byte, key []byte) error {
	if !noHeader[cmd] {
		payload = append(append([]byte(d.cfg.Version), make([]byte, 12)...), payload...)
	}
	enc := ecb(key, pad(payload), true)
	d.wmu.Lock()
	defer d.wmu.Unlock()
	d.seq++
	h := make([]byte, 16)
	binary.BigEndian.PutUint32(h[0:], 0x000055AA)
	binary.BigEndian.PutUint32(h[4:], d.seq)
	binary.BigEndian.PutUint32(h[8:], cmd)
	binary.BigEndian.PutUint32(h[12:], uint32(len(enc)+36))
	msg := append(h, enc...)
	msg = append(msg, mac(key, msg)...)
	msg = append(msg, 0, 0, 0xAA, 0x55)
	d.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := d.conn.Write(msg)
	return err
}

// odczyt jednej ramki; zwraca komendę i odszyfrowaną treść
func readFrame(c net.Conn, key []byte) (uint32, []byte, error) {
	h := make([]byte, 16)
	if _, err := io.ReadFull(c, h); err != nil {
		return 0, nil, err
	}
	if binary.BigEndian.Uint32(h) != 0x000055AA {
		return 0, nil, errors.New("zły nagłówek ramki")
	}
	cmd, n := binary.BigEndian.Uint32(h[8:]), binary.BigEndian.Uint32(h[12:])
	if n < 36 || n > 1<<16 {
		return 0, nil, errors.New("zła długość ramki")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c, body); err != nil {
		return 0, nil, err
	}
	enc := body[:n-36]
	if len(enc)%16 == 4 { // kod powrotu przed danymi
		enc = enc[4:]
	}
	if len(enc) == 0 {
		return cmd, nil, nil
	}
	if !hmac.Equal(mac(key, append(h, body[:n-36]...)), body[n-36:n-4]) {
		return cmd, nil, errors.New("zły podpis ramki (zły klucz?)")
	}
	p := unpad(ecb(key, enc, false))
	if len(p) >= 15 && bytes.HasPrefix(p, []byte("3.")) {
		p = p[15:]
	}
	return cmd, p, nil
}

func (d *dev) connect() error {
	lk := []byte(d.cfg.Key)
	if len(lk) != 16 {
		return errors.New("brak klucza localKey w klima.json")
	}
	c, err := net.DialTimeout("tcp", d.cfg.IP+":6668", 5*time.Second)
	if err != nil {
		return fmt.Errorf("klimatyzator nie odpowiada (%v)", err)
	}
	d.conn = c
	local := make([]byte, 16)
	rand.Read(local)
	if err := d.send(cmdNegStart, local, lk); err != nil {
		c.Close()
		return err
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	cmd, p, err := readFrame(c, lk)
	if err != nil || cmd != cmdNegResp || len(p) < 48 {
		c.Close()
		if err == nil {
			err = errors.New("klimatyzator odrzucił połączenie (zły klucz?)")
		}
		return err
	}
	remote := p[:16]
	if !hmac.Equal(p[16:48], mac(lk, local)) {
		c.Close()
		return errors.New("zły klucz localKey")
	}
	if err := d.send(cmdNegFinish, mac(lk, remote), lk); err != nil {
		c.Close()
		return err
	}
	x := make([]byte, 16)
	for i := range x {
		x[i] = local[i] ^ remote[i]
	}
	d.key = ecb(lk, x, true)
	return nil
}

func (d *dev) merge(p []byte) {
	var m struct {
		Dps  map[string]any `json:"dps"`
		Data struct {
			Dps map[string]any `json:"dps"`
		} `json:"data"`
	}
	if json.Unmarshal(p, &m) != nil {
		return
	}
	dps := m.Dps
	if dps == nil {
		dps = m.Data.Dps
	}
	if dps == nil {
		return
	}
	d.mu.Lock()
	if d.dps == nil {
		d.dps = map[string]any{}
	}
	for k, v := range dps {
		d.dps[k] = v
	}
	d.at, d.err = time.Now(), ""
	d.mu.Unlock()
}

// pętla połączenia: negocjacja, odczyt stanu, heartbeat, ponowne łączenie
func (d *dev) run() {
	for {
		err := d.connect()
		if err == nil {
			log.Printf("połączono z %s", d.cfg.IP)
			stop := make(chan struct{})
			go func() {
				t := time.NewTicker(10 * time.Second)
				defer t.Stop()
				for {
					select {
					case <-stop:
						return
					case <-t.C:
						d.send(cmdHeartbeat, []byte("{}"), d.key)
					}
				}
			}()
			d.send(cmdQueryNew, []byte("{}"), d.key)
			for {
				d.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
				cmd, p, e := readFrame(d.conn, d.key)
				if e != nil {
					err = e
					break
				}
				if len(p) > 0 && (cmd == cmdStatus || cmd == cmdQueryNew || cmd == cmdControl) {
					d.merge(p)
				}
				select {
				case d.resp <- cmd:
				default:
				}
			}
			close(stop)
			d.conn.Close()
		}
		d.mu.Lock()
		d.err = err.Error()
		d.mu.Unlock()
		log.Printf("błąd: %v", err)
		time.Sleep(5 * time.Second)
	}
}

func (d *dev) set(dps map[string]any) error {
	d.mu.Lock()
	ok := d.at.After(time.Time{}) && d.err == ""
	d.mu.Unlock()
	if !ok || d.conn == nil {
		return errors.New("brak połączenia z klimatyzatorem")
	}
	body, _ := json.Marshal(map[string]any{"protocol": 5, "t": time.Now().Unix(), "data": map[string]any{"dps": dps}})
	for len(d.resp) > 0 {
		<-d.resp
	}
	if err := d.send(cmdControl, body, d.key); err != nil {
		return err
	}
	deadline := time.After(4 * time.Second)
	for {
		select {
		case c := <-d.resp:
			if c == cmdStatus {
				return nil
			}
		case <-deadline:
			d.send(cmdQueryNew, []byte("{}"), d.key) // brak potwierdzenia – odśwież stan
			return nil
		}
	}
}

// ---------- timer (lokalny, zapisywany do pliku – przetrwa restart usługi) ----------

type timerState struct {
	At    int64 `json:"at"`    // unix; 0 = brak
	Power bool  `json:"power"` // stan po odliczeniu
}

type timer struct {
	mu   sync.Mutex
	st   timerState
	file string
	t    *time.Timer
	d    *dev
}

func (tm *timer) arm() {
	if tm.t != nil {
		tm.t.Stop()
		tm.t = nil
	}
	if tm.st.At == 0 {
		return
	}
	wait := time.Until(time.Unix(tm.st.At, 0))
	if wait < 0 {
		wait = 0
	}
	st := tm.st
	tm.t = time.AfterFunc(wait, func() {
		for i := 0; i < 6; i++ { // kilka prób, gdyby akurat trwało ponowne łączenie
			if err := tm.d.set(map[string]any{"1": st.Power}); err == nil {
				log.Printf("timer: zasilanie -> %v", st.Power)
				break
			} else {
				log.Printf("timer: %v", err)
			}
			time.Sleep(10 * time.Second)
		}
		tm.mu.Lock()
		if tm.st == st {
			tm.st = timerState{}
			tm.save()
		}
		tm.mu.Unlock()
	})
}
func (tm *timer) save() {
	b, _ := json.Marshal(tm.st)
	os.WriteFile(tm.file, b, 0644)
}
func (tm *timer) setTo(st timerState) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.st = st
	tm.save()
	tm.arm()
}
func (tm *timer) get() timerState {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.st
}

// ---------- HTTP ----------

func isLocal(r *http.Request) bool {
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	_, ts, _ := net.ParseCIDR("100.64.0.0/10")
	return ip.IsLoopback() || ip.IsPrivate() || ts.Contains(ip)
}

func main() {
	listen := flag.String("listen", ":1986", "adres HTTP")
	cfgPath := flag.String("config", "klima.json", "plik konfiguracji")
	arPath := flag.String("ariston", "ariston.json", "dane logowania Ariston (nastawy pompy ciepła)")
	flag.Parse()
	ar, arErr := newAriston(*arPath)
	if arErr != nil {
		log.Printf("ariston: %v", arErr)
	}
	var cfg config
	raw, err := os.ReadFile(*cfgPath)
	if err == nil {
		err = json.Unmarshal(raw, &cfg)
	}
	if cfg.Version == "" {
		cfg.Version = "3.4"
	}
	d := &dev{cfg: cfg, resp: make(chan uint32, 8)}
	cfgErr := err
	tm := &timer{file: strings.TrimSuffix(*cfgPath, ".json") + "-timer.json", d: d}
	if cfgErr == nil {
		go d.run()
		if b, err := os.ReadFile(tm.file); err == nil && json.Unmarshal(b, &tm.st) == nil && tm.st.At > 0 {
			tm.arm()
		}
	} else {
		log.Printf("konfiguracja: %v", cfgErr)
	}

	status := func(w http.ResponseWriter) {
		d.mu.Lock()
		defer d.mu.Unlock()
		e := d.err
		if cfgErr != nil {
			e = "brak pliku klima.json"
		} else if d.at.IsZero() && e == "" {
			e = "łączę…"
		}
		age := 0
		if !d.at.IsZero() {
			age = int(time.Since(d.at).Seconds())
		}
		json.NewEncoder(w).Encode(map[string]any{"name": cfg.Name, "dps": d.dps, "age": age, "seen": !d.at.IsZero(), "error": e, "timer": tm.get(), "now": time.Now().Unix()})
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Method == http.MethodOptions {
			return
		}
		if !isLocal(r) {
			http.Error(w, `{"error":"tylko sieć domowa / Tailscale"}`, http.StatusForbidden)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/klima")
		if strings.HasPrefix(path, "/ariston/") {
			if ar == nil {
				http.Error(w, `{"error":"brak pliku ariston.json"}`, http.StatusNotFound)
				return
			}
			switch path {
			case "/ariston/settings":
				s, err := ar.settings()
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
				json.NewEncoder(w).Encode(s)
			case "/ariston/set":
				var b struct {
					ID    string  `json:"id"`
					Value float64 `json:"value"`
				}
				if r.Method != http.MethodPost || json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&b) != nil || b.ID == "" {
					http.Error(w, `{"error":"zły format"}`, http.StatusBadRequest)
					return
				}
				if err := ar.set(b.ID, b.Value); err != nil {
					w.WriteHeader(http.StatusBadGateway)
					json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
				log.Printf("ariston: %s -> %v", b.ID, b.Value)
				json.NewEncoder(w).Encode(map[string]any{"ok": true})
			default:
				http.Error(w, `{"error":"nie ma"}`, http.StatusNotFound)
			}
			return
		}
		switch path {
		case "/status", "/status/":
			status(w)
		case "/set":
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"POST"}`, http.StatusMethodNotAllowed)
				return
			}
			var b struct {
				Dps map[string]any `json:"dps"`
			}
			if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&b) != nil || len(b.Dps) == 0 {
				http.Error(w, `{"error":"zły format"}`, http.StatusBadRequest)
				return
			}
			if err := d.set(b.Dps); err != nil {
				w.WriteHeader(http.StatusBadGateway)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			status(w)
		case "/timer":
			// {"min":60,"power":false} – za 60 min wyłącz; {"min":0} – anuluj
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"POST"}`, http.StatusMethodNotAllowed)
				return
			}
			var b struct {
				Min   int  `json:"min"`
				Power bool `json:"power"`
			}
			if json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&b) != nil || b.Min < 0 || b.Min > 24*60 {
				http.Error(w, `{"error":"zły format"}`, http.StatusBadRequest)
				return
			}
			if b.Min == 0 {
				tm.setTo(timerState{})
			} else {
				tm.setTo(timerState{At: time.Now().Add(time.Duration(b.Min) * time.Minute).Unix(), Power: b.Power})
			}
			status(w)
		default:
			http.Error(w, `{"error":"nie ma"}`, http.StatusNotFound)
		}
	})
	log.Printf("klima nasłuchuje na %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
