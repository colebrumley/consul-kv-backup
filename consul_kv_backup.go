package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
	"unicode/utf8"

	"github.com/hashicorp/consul/api"
	"gopkg.in/urfave/cli.v1" // imports as package "cli"
)

type valueEnc struct {
	Encoding string `json:"encoding,omitempty"`
	Str      string `json:"value"`
}

type kvJSON struct {
	BackupDate time.Time           `json:"date"`
	Connection map[string]string   `json:"connection_info"`
	Values     map[string]valueEnc `json:"values"`
}

func main() {
	app := cli.NewApp()
	app.Name = "kv-backup"
	app.Usage = "Back up Consul's KV store"
	app.Version = "0.2"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "cacert,r",
			Usage:  "Client CA cert",
			EnvVar: "CONSUL_CA_CERT",
		},
		cli.StringFlag{
			Name:   "prefix",
			Value:  "/",
			Usage:  "Root key prefix",
			EnvVar: "CONSUL_PREFIX",
		},
		cli.StringFlag{
			Name:   "cert,c",
			Usage:  "Client cert",
			EnvVar: "CONSUL_CERT",
		},
		cli.StringFlag{
			Name:   "key,k",
			Usage:  "Client key",
			EnvVar: "CONSUL_KEY",
		},
		cli.StringFlag{
			Name:   "addr,a",
			Value:  "127.0.0.1",
			Usage:  "Consul address (No leading 'http(s)://')",
			EnvVar: "CONSUL_HTTP_ADDR",
		},
		cli.StringFlag{
			Name:   "scheme,s",
			Value:  "http",
			Usage:  "Consul connection scheme (HTTP or HTTPS)",
			EnvVar: "CONSUL_SCHEME",
		},
		cli.IntFlag{
			Name:   "port,p",
			Value:  8500,
			Usage:  "Consul port",
			EnvVar: "CONSUL_PORT",
		},
		cli.BoolFlag{
			Name:   "insecure,i",
			Usage:  "Skip TLS host verification",
			EnvVar: "CONSUL_INSECURE",
		},
		cli.StringFlag{
			Name:   "username,un",
			Usage:  "HTTP Basic auth user",
			EnvVar: "CONSUL_USER",
		},
		cli.StringFlag{
			Name:   "password,pw",
			Usage:  "HTTP Basic auth password",
			EnvVar: "CONSUL_PASS",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:   "backup",
			Usage:  "Dump Consul's KV database to a JSON file",
			Action: backup,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "outfile,o",
					Usage:  "Write output to a file",
					EnvVar: "CONSUL_OUTPUT",
				},
			},
		},
		{
			Name:   "restore",
			Usage:  "restore a JSON backup of Consul's KV store",
			Action: restore,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func getConnectionFromFlags(c *cli.Context) (client *api.Client, bkup *kvJSON, err error) {
	// Start with the default Consul API config
	config := api.DefaultConfig()

	// Create a TLS config to be populated with flag-defined certs if applicable
	tlsConf := &tls.Config{}

	// Set scheme and address:port
	config.Scheme = c.GlobalString("scheme")
	config.Address = fmt.Sprintf("%s:%v", c.GlobalString("addr"), c.GlobalInt("port"))

	// Populate backup metadata
	bkup = &kvJSON{
		BackupDate: time.Now(),
		Connection: map[string]string{},
	}

	// Check for insecure flag
	if c.GlobalBool("insecure") {
		tlsConf.InsecureSkipVerify = true
		bkup.Connection["insecure"] = "true"
	}

	// Load default system root CAs
	// ignore errors since the TLS config
	// will only be applied if --cert and --key
	// are defined
	tlsConf.ClientCAs, _ = loadSystemRootCAs()

	// If --cert and --key are defined, load them and apply the TLS config
	if len(c.GlobalString("cert")) > 0 && len(c.GlobalString("key")) > 0 {
		// Make sure scheme is HTTPS when certs are used, regardless of the flag
		config.Scheme = "https"
		bkup.Connection["cert"] = c.GlobalString("cert")
		bkup.Connection["key"] = c.GlobalString("key")

		// Load cert and key files
		var cert tls.Certificate
		cert, err = tls.LoadX509KeyPair(c.GlobalString("cert"), c.GlobalString("key"))
		if err != nil {
			log.Fatalf("Could not load cert: %v", err)
		}
		tlsConf.Certificates = append(tlsConf.Certificates, cert)

		// If cacert is defined, add it to the cert pool
		// else just use system roots
		if len(c.GlobalString("cacert")) > 0 {
			tlsConf.ClientCAs = addCACert(c.GlobalString("cacert"), tlsConf.ClientCAs)
			tlsConf.RootCAs = tlsConf.ClientCAs
			bkup.Connection["cacert"] = c.GlobalString("cacert")
		}
	}

	bkup.Connection["host"] = config.Scheme + "://" + config.Address

	if config.Scheme == "https" {
		// Set Consul's transport to the TLS config
		config.HttpClient.Transport = &http.Transport{
			TLSClientConfig: tlsConf,
		}
	}

	// Check for HTTP auth flags
	if len(c.GlobalString("user")) > 0 && len(c.GlobalString("pass")) > 0 {
		config.HttpAuth = &api.HttpBasicAuth{
			Username: c.GlobalString("user"),
			Password: c.GlobalString("pass"),
		}
		bkup.Connection["user"] = c.GlobalString("user")
		bkup.Connection["pass"] = c.GlobalString("pass")
	}

	// Generate and return the API client
	client, err = api.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}
	return
}

func dumpOutput(path string, bkup *kvJSON) {
	if len(path) > 0 {
		outBytes, err := json.Marshal(bkup)
		if err != nil {
			log.Fatalf("%v", err)
		}
		if err = ioutil.WriteFile(path, outBytes, 0664); err != nil {
			log.Fatalf("%v", err)
		}
	} else {
		outBytes, err := json.MarshalIndent(bkup, "", "  ")
		if err != nil {
			log.Fatalf("%v", err)
		}
		fmt.Printf("%s\n", string(outBytes))
	}
}

func readBackupFile(path string) (bkup *kvJSON, err error) {
	var f *os.File
	f, err = os.Open(path)
	defer f.Close()
	if err != nil {
		return
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}
	err = json.Unmarshal(b, &bkup)
	return
}

func backup(c *cli.Context) (err error) {
	// Get KV client
	client, backupResult, err := getConnectionFromFlags(c)
	if err != nil {
		return
	}
	kv := client.KV()

	// Dump all
	pairs, _, err := kv.List(c.GlobalString("prefix"), &api.QueryOptions{})
	if err != nil {
		return
	}
	bkup := map[string]valueEnc{}
	for _, p := range pairs {
		validUtf8 := utf8.Valid(p.Value)
		if validUtf8 {
			bkup[p.Key] = valueEnc{"", string(p.Value)}
		} else {
			sEnc := base64.StdEncoding.EncodeToString(p.Value)
			bkup[p.Key] = valueEnc{"base64", sEnc}
		}
	}
	backupResult.Values = bkup

	// Send results to outfile (if defined) or stdout
	dumpOutput(c.String("outfile"), backupResult)

	return
}

func restore(c *cli.Context) (err error) {
	// Get KV client
	client, _, err := getConnectionFromFlags(c)
	if err != nil {
		return
	}
	kv := client.KV()

	// Get backup JSON from file
	bkup, err := readBackupFile(c.Args().First())
	if err != nil {
		return fmt.Errorf("Error getting data: %v", err)
	}

	// restore file contents
	var v string
	for k, ve := range bkup.Values {
		switch ve.Encoding {
		case "base64":
			vd, err := base64.StdEncoding.DecodeString(ve.Str)
			if err != nil {
				return fmt.Errorf("Error decoding the value of key '%s': %v", k, err)
			}
			v = string(vd)
		case "utf8", "":
			v = ve.Str
		default:
			return fmt.Errorf("Unknown encoding '%v' for key '%s'", ve.Encoding, k)
		}

		log.Printf("Restoring key '%s'", k)
		if _, err := kv.Put(&api.KVPair{
			Key:   k,
			Value: []byte(v),
		}, &api.WriteOptions{}); err != nil {
			return fmt.Errorf("Error writing key %s: %v", k, err)
		}
	}
	return
}
