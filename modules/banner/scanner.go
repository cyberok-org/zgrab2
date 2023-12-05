// Package banner provides simple banner grab and matching implementation of the zgrab2.Module.
// It sends a customizble probe (default to "\n") and filters the results based on custom regexp (--pattern)

package banner

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"reflect"
	"regexp"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/nmap"
)

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags
	Probe           string `long:"probe" default:"\\n" description:"Probe to send to the server. Use triple slashes to escape, for example \\\\\\n is literal \\n. Mutually exclusive with --probe-file" `
	ProbeFile       string `long:"probe-file" description:"Read probe from file as byte array (hex). Mutually exclusive with --probe"`
	Pattern         string `long:"pattern" description:"Pattern to match, must be valid regexp."`
	UseTLS          bool   `long:"tls" description:"Sends probe with TLS connection. Loads TLS module command options. "`
	MaxTries        int    `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up. Includes making TLS connection if enabled."`
	Hex             bool   `long:"hex" description:"Store banner value in hex. "`
	ProductMatchers string `long:"product-matchers" description:"Matchers from nmap-service-probes file used to detect product info. Format: <probe>/<service>[,...] (wildcards supported)."`
	zgrab2.TLSFlags
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config          *Flags
	regex           *regexp.Regexp
	probe           []byte
	productMatchers nmap.Matchers
}

// ScanResults instances are returned by the module's Scan function.
type Results struct {
	Banner   string               `json:"banner,omitempty"`
	Length   int                  `json:"length,omitempty"`
	Products []nmap.ExtractResult `json:"products,omitempty"`
}

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("banner", "Banner", module.Description(), 80, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "banner"
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(args []string) error {
	if f.Probe != "\\n" && f.ProbeFile != "" {
		log.Fatal("Cannot set both --probe and --probe-file")
		return zgrab2.ErrInvalidArguments
	}
	return nil
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Fetch a raw banner by sending a static probe and checking the result against a regular expression"
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	var err error
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.regex = regexp.MustCompile(scanner.config.Pattern)
	if len(f.ProbeFile) != 0 {
		scanner.probe, err = ioutil.ReadFile(f.ProbeFile)
		if err != nil {
			log.Fatal("Failed to open probe file")
			return zgrab2.ErrInvalidArguments
		}
	} else {
		strProbe, err := strconv.Unquote(fmt.Sprintf(`"%s"`, scanner.config.Probe))
		if err != nil {
			panic("Probe error")
		}
		scanner.probe = []byte(strProbe)
	}

	scanner.productMatchers = nmap.SelectMatchersGlob(f.ProductMatchers)

	log.Infof("scanner %s inited, matchers count: %d", scanner.GetName(), len(scanner.productMatchers))
	return nil
}

// GetProducts returns nmap matched products.
func (scanner *Scanner) GetProducts(i interface{}) interface{} {

	if sr, ok := i.(*Results); ok && sr != nil && len(sr.Banner) > 0 {
		sr.Products, _ = scanner.productMatchers.ExtractInfoFromBytes([]byte(sr.Banner))
		return sr
	} else {
		log.Infof("type does not match, expected %s, got type: %s , value: %+v", "*banner.Result", reflect.TypeOf(i), i)
		return i
	}
}

var NoMatchError = errors.New("pattern did not match")

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	try := 0
	var (
		conn    net.Conn
		tlsConn *zgrab2.TLSConnection
		err     error
		readerr error
	)
	for try < scanner.config.MaxTries {
		try++
		conn, err = target.Open(&scanner.config.BaseFlags)
		if err != nil {
			continue
		}
		if scanner.config.UseTLS {
			tlsConn, err = scanner.config.TLSFlags.GetTLSConnection(conn)
			if err != nil {
				continue
			}
			if err = tlsConn.Handshake(); err != nil {
				continue
			}
			conn = tlsConn
		}

		break
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	var ret []byte
	try = 0
	for try < scanner.config.MaxTries {
		try++
		_, err = conn.Write(scanner.probe)
		ret, readerr = zgrab2.ReadAvailable(conn)
		if err != nil {
			continue
		}
		if readerr != io.EOF && readerr != nil {
			continue
		}
		break
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if readerr != io.EOF && readerr != nil {
		return zgrab2.TryGetScanStatus(readerr), nil, readerr
	}

	results := Results{
		Banner: string(ret),
		Length: len(ret),
	}
	if scanner.config.Hex {
		results.Banner = hex.EncodeToString(ret)
	}

	// var mTotal int
	// var mPassed int
	// var mError int
	// t1 := time.Now().UTC()

	// results.Products, mTotal, mTotal, mError, _ = scanner.productMatchers.ExtractInfoFromBytes(ret)

	// log.Infof("target: %s; port: %s banner size %d, took %s, match total: %d, match passed: %d, match error: %d",
	// 	target.IP.String(), target.Tag, len(ret), time.Now().UTC().Sub(t1), mTotal, mPassed, mError)

	//results.Products, _ = scanner.productMatchers.ExtractInfoFromBytes(ret)

	if scanner.regex.Match(ret) {
		return zgrab2.SCAN_SUCCESS, &results, nil
	}
	return zgrab2.SCAN_PROTOCOL_ERROR, &results, NoMatchError
}
