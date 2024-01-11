package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	webAuthn *webauthn.WebAuthn
	err      error
)

type User struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

// WebAuthnID provides the user handle of the user account. A user handle is an opaque byte sequence with a maximum
// size of 64 bytes, and is not meant to be displayed to the user.
func (user *User) WebAuthnID() []byte {
	return user.ID
}

// WebAuthnName provides the name attribute of the user account during registration and is a human-palatable name for the user
// account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party SHOULD let the user
// choose this, and SHOULD NOT restrict the choice more than necessary.
// Used by protocol.CredentialEntity.
func (user *User) WebAuthnName() string {
	return user.Name
}

// WebAuthnDisplayName provides the name attribute of the user account during registration and is a human-palatable name for the user
// account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party SHOULD let the user
// choose this, and SHOULD NOT restrict the choice more than necessary.
func (user *User) WebAuthnDisplayName() string {
	return user.DisplayName
}

// DEPRECATED WebAuthnIcon returns a URL to an icon
func (user *User) WebAuthnIcon() string {
	return ""
}

func (user *User) WebAuthnCredentials() []webauthn.Credential {
	return user.Credentials
}

// Your initialization function
func main() {
	wconfig := &webauthn.Config{
		RPDisplayName: "Go Webauthn",                     // Display Name for your site
		RPID:          "localhost",                       // Generally the FQDN for your site
		RPOrigins:     []string{"http://localhost:8080"}, // The origin URLs allowed for WebAuthn requests
	}

	if webAuthn, err = webauthn.New(wconfig); err != nil {
		fmt.Println(err)
	}

	var ses *webauthn.SessionData
	user := &User{
		ID:          []byte("1234567890"),
		Name:        "test",
		Credentials: []webauthn.Credential{},
	}

	beginRegistration := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		options, session, err := webAuthn.BeginRegistration(user)
		log.Println("Begin", err)
		ses = session
		json.NewEncoder(w).Encode(options)
	}

	finishRegistration := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		credential, err := webAuthn.FinishRegistration(user, *ses, r)
		if err != nil {
			log.Println("FINISH", err)
			return
		}

		user.Credentials = append(user.Credentials, *credential)
		// d, _ := json.MarshalIndent(credential, "", "  ")
		// fmt.Println(string(d))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"verified": true}`))
	}

	beginLogin := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		opts, session, err := webAuthn.BeginLogin(user)
		if err != nil {
			log.Println("BeginLogin", err)
			return
		}
		ses = session
		json.NewEncoder(w).Encode(opts)
	}

	finishLogin := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		crds, err := webAuthn.FinishLogin(user, *ses, r)
		if err != nil {
			log.Println("finishLogin", err)
			return
		}
		user.Credentials = append(user.Credentials, *crds)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"verified": true}`))
	}

	http.Handle("/", http.FileServer(http.Dir("./static")))
	http.HandleFunc("/start", beginRegistration)
	http.HandleFunc("/finish", finishRegistration)
	http.HandleFunc("/login/start", beginLogin)
	http.HandleFunc("/login/finish", finishLogin)

	http.ListenAndServe(":8080", nil)
}
