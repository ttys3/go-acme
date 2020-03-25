package fs

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/ttys3/go-acme/backend"
	"github.com/ttys3/go-acme/types"
)

const (
	BackendName   = "fs"
	storageDirEnv = "GO_ACME_STORAGE_DIR"
)

type storage struct {
	StorageDir  string
	storageLock sync.RWMutex
}

// Name returns the display name of the backend.
func (s *storage) Name() string {
	return BackendName
}

func (s *storage) key(domain string) string {
	// save *.example.com to file _wildcard.example.com
	if strings.HasPrefix(domain, "*") {
		domain = strings.TrimPrefix(domain, "*")
		domain = "_wildcard" + domain
	}
	return path.Join(s.StorageDir, domain) + ".json"
}

// SaveAccount saves the account to the filesystem.
func (s *storage) SaveAccount(account *types.Account) error {
	s.storageLock.Lock()
	defer s.storageLock.Unlock()
	// write account to file
	data, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return err
	}
	savePath := s.key(account.DomainsCertificate.Domain.Main)
	if err := ioutil.WriteFile(savePath, data, 0644); err != nil {
		return err
	}
	log.Printf("[ACME fs backend] saved account to: %s", savePath)
	// save to file
	if account.KeyPath != "" && account.CertPath != "" {
		if err := ioutil.WriteFile(account.KeyPath, account.DomainsCertificate.Certificate.PrivateKey, 0644); err != nil {
			return err
		}
		log.Printf("[ACME fs backend] saved key to: %s", account.KeyPath)

		if err := ioutil.WriteFile(account.CertPath, account.DomainsCertificate.Certificate.Certificate, 0644); err != nil {
			return err
		}
		log.Printf("[ACME fs backend] saved cert to: %s", account.CertPath)
	}
	return nil
}

// LoadAccount loads the account from the filesystem.
func (s *storage) LoadAccount(domain string) (*types.Account, error) {
	storageFile := s.key(domain)
	// if certificates in storage, load them
	if fileInfo, err := os.Stat(storageFile); err != nil || fileInfo.Size() == 0 {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	s.storageLock.RLock()
	defer s.storageLock.RUnlock()

	account := types.Account{
		DomainsCertificate: &types.DomainCertificate{},
	}
	file, err := ioutil.ReadFile(storageFile)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(file, &account); err != nil {
		return nil, fmt.Errorf("Error loading account: %v", err)
	}
	log.Printf("[ACME fs backend] loaded account from : %s", storageFile)
	return &account, nil
}

func newBackend() (backend.Interface, error) {
	storageDir := os.Getenv(storageDirEnv)
	if storageDir != "" {
		return &storage{StorageDir: storageDir}, nil

	}
	// default to current directory
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	return &storage{StorageDir: cwd}, nil
}

func init() {
	backend.RegisterBackend(BackendName, func() (backend.Interface, error) {
		return newBackend()
	})
}
