package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"

	"github.com/docker/attest"
	"github.com/docker/attest-provider/pkg/utils"
	"github.com/docker/attest/config"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/policy"
	"github.com/docker/attest/tuf"
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
	opts *ValidateHandlerOptions
}

func NewValidateHandler(ctx context.Context, opts *ValidateHandlerOptions) (http.Handler, error) {
	handler := &validateHandler{opts: opts}

	// a TUF client can only be used once, so we need to create a new one for each request.
	// we create this one up front to ensure that the TUF root is valid and to pre-load the metadata.
	// TODO: this pre-loading works for the root, targets, snapshot, and timestamp roles, but not for delegated roles.
	_, err := handler.newVerifier(ctx)
	if err != nil {
		// if this failed, don't return an error, just log it and continue
		// this prevents the server from getting into a crash loop if the TUF repo is down or broken,
		// and we can still recover if the TUF repo comes back up.
		klog.ErrorS(err, "failed to initialize TUF client")
	}

	klog.Infof("validate handler initialized with %s TUF root", opts.TUFRoot)

	return handler, nil
}

func (h *validateHandler) newVerifier(ctx context.Context) (attest.Verifier, error) {
	root, err := tuf.GetEmbeddedRoot(h.opts.TUFRoot)
	if err != nil {
		return nil, err
	}

	policyOpts := &policy.Options{
		TUFClientOptions: &tuf.ClientOptions{
			InitialRoot:    root.Data,
			Path:           h.opts.TUFOutputPath,
			MetadataSource: h.opts.TUFMetadataURL,
			TargetsSource:  h.opts.TUFTargetsURL,
			VersionChecker: tuf.NewDefaultVersionChecker(),
		},
		LocalTargetsDir:  h.opts.PolicyCacheDir,
		LocalPolicyDir:   h.opts.PolicyDir,
		AttestationStyle: config.AttestationStyle(h.opts.AttestationStyle),
		ReferrersRepo:    h.opts.ReferrersRepo,
		Debug:            true,
	}
	verifier, err := attest.NewVerifier(ctx, policyOpts)
	if err != nil {
		return nil, err
	}
	return verifier, nil
}

func (h *validateHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			klog.Error(string(debug.Stack()))
			klog.ErrorS(fmt.Errorf("%v", r), "panic occurred")
		}
	}()

	ctx := req.Context()

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

	// create a new verifier for each request
	attest, err := h.newVerifier(ctx)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to create verifier: %v", err), w)
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

		result, err := attest.Verify(ctx, src)
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
