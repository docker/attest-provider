package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/attest-provider/pkg/handler"
	"github.com/docker/attest-provider/pkg/utils"
	"github.com/docker/attest/useragent"

	"k8s.io/klog/v2"
)

const (
	readHeaderTimeout = 1 * time.Second
)

const (
	defaultPort = 8090

	certName = "tls.crt"
	keyName  = "tls.key"
)

var (
	certDir               string
	clientCAFile          string
	port                  int
	handlerTimeoutSeconds int

	tufRoot       string
	tufChannel    string
	tufoutputPath string
	metadataURL   string
	targetsURL    string

	policyDir      string
	policyCacheDir string

	attestationStyle string
	referrersRepo    string
	parameters       nameValuePairs
)

const (
	defaultMetadataURL = "registry-1.docker.io/docker/tuf-metadata:latest"
	defaultTargetsURL  = "registry-1.docker.io/docker/tuf-targets"
	defaultTUFChannel  = ""
)

var (
	defaultTUFOutputPath  = filepath.Join("/tuf_temp", ".docker", "tuf")
	defaultPolicyCacheDir = filepath.Join("/tuf_temp", ".docker", "policy")
	version               = ""
)

type nameValuePairs map[string]string

func (nvp *nameValuePairs) String() string {
	return fmt.Sprintf("%v", *nvp)
}

func (nvp *nameValuePairs) Set(value string) error {
	parts := strings.Split(value, ",")
	if len(parts) == 1 {
		return fmt.Errorf("invalid format, expected name=value")
	}
	for _, part := range parts {
		kv := strings.Split(part, "=")
		if len(kv) != 2 {
			return fmt.Errorf("invalid format, expected name=value")
		}
		(*nvp)[kv[0]] = kv[1]
	}
	return nil
}

var timeoutError = string(utils.GatekeeperError("operation timed out"))

func init() {
	klog.InitFlags(nil)
	flag.StringVar(&certDir, "cert-dir", "", "path to directory containing TLS certificates")
	flag.StringVar(&clientCAFile, "client-ca-file", "", "path to client CA certificate")
	flag.IntVar(&port, "port", defaultPort, "Port for the server to listen on")
	flag.IntVar(&handlerTimeoutSeconds, "handler-timeout", 25, "timeout for handler in seconds")

	flag.StringVar(&tufRoot, "tuf-root", "prod", "specify embedded tuf root [dev, staging, prod], default [prod]")
	flag.StringVar(&tufChannel, "tuf-channel", defaultTUFChannel, "release channel [prod, testing], default [prod]")
	flag.StringVar(&metadataURL, "tuf-metadata-source", defaultMetadataURL, "source (URL or repo) for TUF metadata")
	flag.StringVar(&targetsURL, "tuf-targets-source", defaultTargetsURL, "source (URL or repo) for TUF targets")
	flag.StringVar(&tufoutputPath, "tuf-output-path", defaultTUFOutputPath, "local dir to store TUF repo metadata")

	flag.StringVar(&policyDir, "local-policy-dir", "", "path to local policy directory (overrides TUF policy)")
	flag.StringVar(&policyCacheDir, "policy-cache-dir", defaultPolicyCacheDir, "path to store policy downloaded from TUF")

	flag.StringVar(&attestationStyle, "attestation-style", "referrers", "attestation style [referrers, attached]")
	flag.StringVar(&referrersRepo, "referrers-source", "", "repo from which to fetch Referrers for attestation lookup")

	parameters = make(nameValuePairs)
	flag.Var(&parameters, "parameters", "policy parameters in name=value,name1,value1 format")

	flag.Parse()
}

func main() {
	mux := http.NewServeMux()
	handlerTimeout := time.Duration(handlerTimeoutSeconds) * time.Second

	ctx := useragent.Set(context.Background(), "attest-provider/"+version+" (docker)")

	if tufChannel == "prod" {
		tufChannel = ""
	}

	validateHandler, err := handler.NewValidateHandler(ctx, &handler.ValidateHandlerOptions{
		TUFRoot:          tufRoot,
		TUFChannel:       tufChannel,
		TUFOutputPath:    tufoutputPath,
		TUFMetadataURL:   metadataURL,
		TUFTargetsURL:    targetsURL,
		PolicyDir:        policyDir,
		PolicyCacheDir:   policyCacheDir,
		AttestationStyle: attestationStyle,
		ReferrersRepo:    referrersRepo,
		Parameters:       parameters,
	})
	if err != nil {
		klog.ErrorS(err, "unable to create validate handler")
		os.Exit(1)
	}

	mutateHandler, err := handler.NewMutateHandler()
	if err != nil {
		klog.ErrorS(err, "unable to create validate handler")
		os.Exit(1)
	}

	mux.Handle("POST /validate", http.TimeoutHandler(validateHandler, handlerTimeout, timeoutError))
	mux.Handle("POST /mutate", http.TimeoutHandler(mutateHandler, handlerTimeout, timeoutError))
	mux.Handle("GET /ready", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if clientCAFile != "" {
		klog.InfoS("loading Gatekeeper's CA certificate", "clientCAFile", clientCAFile)
		caCert, err := os.ReadFile(clientCAFile)
		if err != nil {
			klog.ErrorS(err, "unable to load Gatekeeper's CA certificate", "clientCAFile", clientCAFile)
			os.Exit(1)
		}

		clientCAs := x509.NewCertPool()
		clientCAs.AppendCertsFromPEM(caCert)

		config.ClientCAs = clientCAs
		config.ClientAuth = tls.VerifyClientCertIfGiven
		server.TLSConfig = config
	}

	if certDir != "" {
		certFile := filepath.Join(certDir, certName)
		keyFile := filepath.Join(certDir, keyName)

		klog.InfoS("starting external data provider server", "port", port, "certFile", certFile, "keyFile", keyFile)
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
			klog.ErrorS(err, "unable to start external data provider server")
			os.Exit(1)
		}
	} else {
		klog.Error("TLS certificates are not provided, the server will not be started")
		os.Exit(1)
	}
}
