package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"

	"github.com/docker/attest-provider/pkg/utils"
	"github.com/docker/attest/pkg/attest"
	"github.com/docker/attest/pkg/config"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	"github.com/docker/attest/pkg/tuf"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"k8s.io/klog/v2"
)

type ValidationResult struct {
	Outcome    attest.Outcome     `json:"outcome"`
	Input      *policy.Input      `json:"input"`
	VSA        *intoto.Statement  `json:"vsa"`
	Violations []policy.Violation `json:"violations"`
}

type ValidateHandlerOptions struct {
	TUFRoot        string
	TUFOutputPath  string
	TUFMetadataURL string
	TUFTargetsURL  string

	PolicyDir      string
	PolicyCacheDir string

	AttestationStyle string
	ReferrersRepo    string
}

type validateHandler struct {
	opts     *ValidateHandlerOptions
	verifier attest.Verifier
}

func NewValidateHandler(opts *ValidateHandlerOptions) (http.Handler, error) {
	root, err := tuf.GetEmbeddedRoot(opts.TUFRoot)
	if err != nil {
		// if this failed, don't return an error, just log it and continue
		// this prevents the server from getting into a crash loop if the TUF repo is down or broken,
		// and we can still recover if the TUF repo comes back up.
		klog.ErrorS(err, "failed to initialize TUF client")
	}
	vopts := &policy.Options{
		LocalTargetsDir:  opts.PolicyCacheDir,
		LocalPolicyDir:   opts.PolicyDir,
		AttestationStyle: config.AttestationStyle(opts.AttestationStyle),
		ReferrersRepo:    opts.ReferrersRepo,
		TUFClientOptions: &tuf.ClientOptions{
			InitialRoot:    root.Data,
			Path:           opts.TUFOutputPath,
			MetadataSource: opts.TUFMetadataURL,
			TargetsSource:  opts.TUFTargetsURL,
			VersionChecker: tuf.NewDefaultVersionChecker(),
		},
	}
	verifier, err := attest.NewVerifier(vopts)
	if err != nil {
		// if this failed, don't return an error, just log it and continue
		// this prevents the server from getting into a crash loop if the TUF repo is down or broken,
		// and we can still recover if the TUF repo comes back up.
		klog.ErrorS(err, "failed to initialize TUF client")
	}
	handler := &validateHandler{opts: opts, verifier: verifier}

	klog.Infof("validate handler initialized with %s TUF root", opts.TUFRoot)

	return handler, nil
}

func (h *validateHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			klog.Error(string(debug.Stack()))
			klog.ErrorS(fmt.Errorf("%v", r), "panic occurred")
		}
	}()

	ctx := req.Context()
	debug := true
	ctx = policy.WithPolicyEvaluator(ctx, policy.NewRegoEvaluator(debug))

	// read request body
	requestBody, err := io.ReadAll(req.Body)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), w)
		return
	}

	klog.InfoS("received request", "body", requestBody)

	// parse request body
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}

	results := make([]externaldata.Item, 0)
	for _, key := range providerRequest.Request.Keys {
		platform := "linux/amd64"
		src, err := oci.ParseImageSpec(key, oci.WithPlatform(platform))
		if err != nil {
			utils.SendResponse(nil, err.Error(), w)
			return
		}

		result, err := h.verifier.Verify(ctx, src)
		if err != nil {
			utils.SendResponse(nil, err.Error(), w)
			return
		}

		results = append(results, externaldata.Item{
			Key: key,
			Value: ValidationResult{
				Outcome:    result.Outcome,
				Input:      result.Input,
				VSA:        result.VSA,
				Violations: result.Violations,
			},
		})
	}
	utils.SendResponse(&results, "", w)
}
