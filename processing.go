package zgrab2

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2/lib/output"
)

// Grab contains all scan responses for a single host
type Grab struct {
	IP     string                  `json:"ip,omitempty"`
	Domain string                  `json:"domain,omitempty"`
	Tag    string                  `json:"-"`
	Data   map[string]ScanResponse `json:"data,omitempty"`
}

// ScanTarget is the host that will be scanned
type ScanTarget struct {
	IP     net.IP
	Domain string
	Tag    string
	Port   *uint
}

func (target ScanTarget) String() string {
	if target.IP == nil && target.Domain == "" {
		return "<empty target>"
	}
	res := ""
	if target.IP != nil && target.Domain != "" {
		res = target.Domain + "(" + target.IP.String() + ")"
	} else if target.IP != nil {
		res = target.IP.String()
	} else {
		res = target.Domain
	}
	if target.Tag != "" {
		res += " tag:" + target.Tag
	}
	return res
}

// Host gets the host identifier as a string: the IP address if it is available,
// or the domain if not.
func (target *ScanTarget) Host() string {
	if target.IP != nil {
		return target.IP.String()
	} else if target.Domain != "" {
		return target.Domain
	}
	log.Fatalf("Bad target %s: no IP/Domain", target.String())
	panic("unreachable")
}

// Open connects to the ScanTarget using the configured flags, and returns a net.Conn that uses the configured timeouts for Read/Write operations.
func (target *ScanTarget) Open(flags *BaseFlags) (net.Conn, error) {
	var port uint
	// If the port is supplied in ScanTarget, let that override the cmdline option
	if target.Port != nil {
		port = *target.Port
	} else {
		port = flags.Port
	}

	address := net.JoinHostPort(target.Host(), fmt.Sprintf("%d", port))
	return DialTimeoutConnection("tcp", address, flags.Timeout, flags.BytesReadLimit)
}

// OpenTLS connects to the ScanTarget using the configured flags, then performs
// the TLS handshake. On success error is nil, but the connection can be non-nil
// even if there is an error (this allows fetching the handshake log).
func (target *ScanTarget) OpenTLS(baseFlags *BaseFlags, tlsFlags *TLSFlags) (*TLSConnection, error) {
	conn, err := tlsFlags.Connect(target, baseFlags)
	if err != nil {
		return conn, err
	}
	err = conn.Handshake()
	return conn, err
}

// OpenUDP connects to the ScanTarget using the configured flags, and returns a net.Conn that uses the configured timeouts for Read/Write operations.
// Note that the UDP "connection" does not have an associated timeout.
func (target *ScanTarget) OpenUDP(flags *BaseFlags, udp *UDPFlags) (net.Conn, error) {
	var port uint
	// If the port is supplied in ScanTarget, let that override the cmdline option
	if target.Port != nil {
		port = *target.Port
	} else {
		port = flags.Port
	}
	address := net.JoinHostPort(target.Host(), fmt.Sprintf("%d", port))
	var local *net.UDPAddr
	if udp != nil && (udp.LocalAddress != "" || udp.LocalPort != 0) {
		local = &net.UDPAddr{}
		if udp.LocalAddress != "" && udp.LocalAddress != "*" {
			local.IP = net.ParseIP(udp.LocalAddress)
		}
		if udp.LocalPort != 0 {
			local.Port = int(udp.LocalPort)
		}
	}
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", local, remote)
	if err != nil {
		return nil, err
	}
	return NewTimeoutConnection(nil, conn, flags.Timeout, 0, 0, flags.BytesReadLimit), nil
}

// BuildGrabFromInputResponse constructs a Grab object for a target, given the
// scan responses.
func BuildGrabFromInputResponse(t *ScanTarget, responses map[string]ScanResponse) *Grab {
	var ipstr string

	if t.IP != nil {
		ipstr = t.IP.String()
	}
	return &Grab{
		IP:     ipstr,
		Domain: t.Domain,
		Tag:    t.Tag,
		Data:   responses,
	}
}

// EncodeGrab serializes a Grab to JSON, handling the debug fields if necessary.
func EncodeGrab(raw *Grab, includeDebug bool) ([]byte, error) {
	var outputData interface{}
	if includeDebug {
		outputData = raw
	} else {
		// If the caller doesn't explicitly request debug data, strip it out.
		// TODO: Migrate this to the ZMap fork of sheriff, once it's more
		// stable.
		processor := output.Processor{Verbose: false}
		stripped, err := processor.Process(raw)
		if err != nil {
			log.Debugf("Error processing results: %v", err)
			stripped = raw
		}
		outputData = stripped
	}
	return json.Marshal(outputData)
}

// grabTarget calls handler for each action
func grabTarget(input ScanTarget, m *Monitor) []byte {
	moduleResult := make(map[string]ScanResponse)

	for _, scannerName := range orderedScanners {
		scanner := scanners[scannerName]
		trigger := (*scanner).GetTrigger()
		if input.Tag != trigger {
			continue
		}
		defer func(name string) {
			if e := recover(); e != nil {
				log.Errorf("Panic on scanner %s when scanning target %s: %#v", scannerName, input.String(), e)
				// Bubble out original error (with original stack) in lieu of explicitly logging the stack / error
				panic(e)
			}
		}(scannerName)
		log.Infof("call scanner with %s, %s, %s", input.IP.String(), input.Tag, scannerName)
		name, res := RunScanner(*scanner, m, input)
		moduleResult[name] = res
		if res.Error != nil && !config.Multiple.ContinueOnError {
			break
		}
		if res.Status == SCAN_SUCCESS && config.Multiple.BreakOnSuccess {
			break
		}
	}
	log.Info("after loop in grabTarget")
	raw := BuildGrabFromInputResponse(&input, moduleResult)
	result, err := EncodeGrab(raw, includeDebugOutput())
	if err != nil {
		log.Errorf("unable to marshal data: %s", err)
	}

	return result
}

func matchProducts(g *Grab) []byte {
	for _, scannerName := range orderedScanners {
		scanner := scanners[scannerName]
		trigger := (*scanner).GetTrigger()
		if g.Tag != trigger {
			continue
		}
		if pr, ok := g.Data[scannerName]; ok {
			if pr.Result != nil {
				(*scanner).GetProducts(pr.Result)
			}
		}
	}
	result, err := EncodeGrab(g, includeDebugOutput())
	if err != nil {
		log.Errorf("unable to marshal data: %s", err)
	}
	return result
}

// grabTarget calls handler for each action
func grabTarget2(input ScanTarget, m *Monitor) *Grab {
	moduleResult := make(map[string]ScanResponse)
	for _, scannerName := range orderedScanners {
		//t1 := time.Now().UTC()
		scanner := scanners[scannerName]
		trigger := (*scanner).GetTrigger()
		if input.Tag != trigger {
			continue
		}
		defer func(name string) {
			if e := recover(); e != nil {
				log.Errorf("Panic on scanner %s when scanning target %s: %#v", scannerName, input.String(), e)
				// Bubble out original error (with original stack) in lieu of explicitly logging the stack / error
				panic(e)
			}
		}(scannerName)

		name, res := RunScanner(*scanner, m, input)

		//log.Infof("SCAN %s, tog: %s, scan: %s, time: %s",
		//	input.IP.String(), input.Tag, scannerName, time.Now().UTC().Sub(t1))

		moduleResult[name] = res
		if res.Error != nil && !config.Multiple.ContinueOnError {
			break
		}
		if res.Status == SCAN_SUCCESS && config.Multiple.BreakOnSuccess {
			break
		}
	}
	return BuildGrabFromInputResponse(&input, moduleResult)
}

// Process sets up an output encoder, input reader, and starts grab workers.
func Process(mon *Monitor) {
	workers := config.Senders
	matchers := config.NmapMatchers
	processQueue := make(chan ScanTarget, workers*4)
	matchersQueue := make(chan *Grab, matchers*8)
	outputQueue := make(chan []byte, workers*2)

	//Create wait groups
	var workerDone sync.WaitGroup
	var outputDone sync.WaitGroup
	var matcherDone sync.WaitGroup
	workerDone.Add(int(workers))
	matcherDone.Add(int(matchers))
	outputDone.Add(1)

	// Start nmap matchers goroutine
	for i := 0; i < matchers; i++ {
		go func() {
			for grab := range matchersQueue {
				result := matchProducts(grab)
				outputQueue <- result
			}
			matcherDone.Done()
		}()
	}

	// Start the output encoder
	go func() {
		defer outputDone.Done()
		if err := config.outputResults(outputQueue); err != nil {
			log.Fatal(err)
		}
	}()

	//Start all the workers
	for i := 0; i < workers; i++ {
		go func(i int) {
			for _, scannerName := range orderedScanners {
				scanner := *scanners[scannerName]
				scanner.InitPerSender(i)
			}
			for obj := range processQueue {
				for run := uint(0); run < uint(config.ConnectionsPerHost); run++ {
					//log.Infof("ASK: %+v", obj)
					//t1 := time.Now().UTC()
					result := grabTarget2(obj, mon)
					matchersQueue <- result
					//log.Infof("RECV: %+v, TIME: %s", obj, time.Duration(time.Now().UTC().Sub(t1)))
				}
			}
			workerDone.Done()
		}(i)
	}
	if err := config.inputTargets(processQueue); err != nil {
		log.Fatal(err)
	}
	close(processQueue)
	workerDone.Wait()
	close(matchersQueue)
	matcherDone.Wait()
	close(outputQueue)
	outputDone.Wait()
}
