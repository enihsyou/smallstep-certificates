package api

import (
    "io"
    "net/http"
    "os"

    "github.com/smallstep/certificates/api/render"
    "github.com/smallstep/certificates/authority/config"
    "github.com/smallstep/certificates/errs"
)

// RootCRL is an HTTP handler that returns the current Root CRL in DER or PEM format
func RootCRL(w http.ResponseWriter, r *http.Request) {
	type AuthorityHaveConfig interface {
		GetConfig() *config.Config
	}

	var rootCRL string
	authorityConfig := mustAuthority(r.Context()).(AuthorityHaveConfig).GetConfig()
	if authorityConfig.CRL != nil {
		rootCRL = authorityConfig.CRL.RootCRL
	}
	if rootCRL == "" {
		render.Error(w, r, errs.New(http.StatusNotFound, "no Root CRL configured"))
		return
	}

	w.Header().Add("Content-Type", "application/x-pem-file")
	w.Header().Add("Content-Disposition", "attachment; filename=\"root.crl\"")

	f, err := os.Open(rootCRL)
	if err != nil {
		render.Error(w, r, errs.New(http.StatusNotFound, "Root CRL is not available"))
		return
	}
    _, _ = io.Copy(w, f)
    defer f.Close()
}
