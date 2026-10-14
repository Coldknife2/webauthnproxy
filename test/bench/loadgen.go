//go:build ignore

// loadgen: minimal HTTP load generator (keep-alive, fixed concurrency) used by bench.sh.
//
//	go run loadgen.go -url http://127.0.0.1:8080/_wap/verify -c 32 -d 10s \
//	  -H 'X-Forwarded-Host: app.example.com' -H 'Cookie: wap_session=…'
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type headers []string

func (h *headers) String() string     { return strings.Join(*h, ",") }
func (h *headers) Set(v string) error { *h = append(*h, v); return nil }

func main() {
	url := flag.String("url", "", "target URL")
	c := flag.Int("c", 32, "concurrent connections")
	d := flag.Duration("d", 10*time.Second, "duration")
	var hs headers
	flag.Var(&hs, "H", "header 'Name: value' (repeatable; 'Host' sets the Host header)")
	flag.Parse()
	if *url == "" {
		fmt.Fprintln(os.Stderr, "-url required")
		os.Exit(2)
	}
	client := &http.Client{
		Transport:     &http.Transport{MaxIdleConnsPerHost: *c, MaxConnsPerHost: *c},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var (
		mu     sync.Mutex
		lats   []time.Duration
		codes  = map[int]int{}
		wg     sync.WaitGroup
		stop   = time.Now().Add(*d)
		errors int
	)
	for i := 0; i < *c; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local []time.Duration
			lc := map[int]int{}
			le := 0
			for time.Now().Before(stop) {
				req, _ := http.NewRequest("GET", *url, nil)
				for _, h := range hs {
					k, v, _ := strings.Cut(h, ":")
					v = strings.TrimSpace(v)
					if strings.EqualFold(k, "Host") {
						req.Host = v
					} else {
						req.Header.Set(k, v)
					}
				}
				t := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					le++
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				local = append(local, time.Since(t))
				lc[resp.StatusCode]++
			}
			mu.Lock()
			lats = append(lats, local...)
			for k, v := range lc {
				codes[k] += v
			}
			errors += le
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	n := len(lats)
	if n == 0 {
		fmt.Println("no successful request")
		os.Exit(1)
	}
	p := func(q float64) time.Duration { return lats[int(float64(n-1)*q)] }
	fmt.Printf("requests=%d errors=%d rps=%.0f p50=%v p99=%v codes=%v\n",
		n, errors, float64(n)/d.Seconds(), p(0.5).Round(time.Microsecond), p(0.99).Round(time.Microsecond), codes)
}
