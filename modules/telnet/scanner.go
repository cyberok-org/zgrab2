// Package telnet provides a zgrab2 module that scans for telnet daemons.
// Default Port: 23 (TCP)
//
// The --max-read-size flag allows setting a ceiling to the number of bytes
// that will be read for the banner.
//
// The scan negotiates the options and attempts to grab the banner, using the
// same behavior as the original zgrab.
//
// The output contains the banner and the negotiated options, in the same
// format as the original zgrab.
package telnet

import (
	"reflect"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/nmap"
)

// Flags holds the command-line configuration for the Telnet scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	MaxReadSize     int    `long:"max-read-size" description:"Set the maximum number of bytes to read when grabbing the banner" default:"65536"`
	Banner          bool   `long:"force-banner" description:"Always return banner if it has non-zero bytes"`
	Verbose         bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	ProductMatchers string `long:"product-matchers" default:"*/telnet" description:"Matchers from nmap-service-probes file used to detect product info. Format: <probe>/<service>[,...] (wildcards supported)."`
}

// Module implements the zgrab2.Module interface.
type Module struct{}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config          *Flags
	productMatchers nmap.Matchers
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("telnet", "telnet", module.Description(), 23, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Fetch a telnet banner"
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return ""
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.productMatchers = nmap.SelectMatchersGlob(f.ProductMatchers)
	log.Infof("scanner %s inited, matchers count: %d", scanner.GetName(), len(scanner.productMatchers))

	return nil
}

// GetProducts returns nmap matched products.
func (scanner *Scanner) GetProducts(i interface{}) interface{} {
	if sr, ok := i.(*TelnetLog); ok && sr != nil {

		sr.Products, _ = scanner.productMatchers.ExtractInfoFromBytes([]byte(sr.Banner))
		return sr
	} else {
		log.Infof("type does not match, expected %s, got type: %s , value: %+v", "*TelnetLog", reflect.TypeOf(i), i)
		return i
	}
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
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
	return "telnet"
}

// Scan connects to the target (default port TCP 23) and attempts to grab the Telnet banner.
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()
	result := new(TelnetLog)
	if err := GetTelnetBanner(result, conn, scanner.config.MaxReadSize); err != nil {
		if scanner.config.Banner && len(result.Banner) > 0 {
			return zgrab2.TryGetScanStatus(err), result, err
		} else {
			return zgrab2.TryGetScanStatus(err), result.getResult(), err
		}
	}

	// var mTotal int
	// var mPassed int
	// var mError int
	// t1 := time.Now().UTC()

	// result.Products, mTotal, mTotal, mError, _ = scanner.productMatchers.ExtractInfoFromBytes([]byte(result.Banner))

	// log.Infof("target: %s; port: %s banner size %d, took %s, match total: %d, match passed: %d, match error: %d",
	// 	target.IP.String(), target.Tag, len(result.Banner), time.Now().UTC().Sub(t1), mTotal, mPassed, mError)

	//result.Products, _ = scanner.productMatchers.ExtractInfoFromBytes([]byte(result.Banner))

	return zgrab2.SCAN_SUCCESS, result, nil
}
