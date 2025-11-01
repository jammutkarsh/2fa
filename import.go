package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

// TwoFASExport represents the structure of a 2FAS export file
type TwoFASExport struct {
	Services []TwoFASService `json:"services"`
}

// TwoFASService represents a single service in a 2FAS export
type TwoFASService struct {
	Name   string    `json:"name"`
	Secret string    `json:"secret"`
	OTP    TwoFASOTP `json:"otp"`
}

// TwoFASOTP contains the OTP configuration for a 2FAS service
type TwoFASOTP struct {
	Label     string `json:"label"`
	Account   string `json:"account"`
	Issuer    string `json:"issuer"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Algorithm string `json:"algorithm"`
	TokenType string `json:"tokenType"`
}

// import2fas imports keys from a 2FAS JSON export file
func (c *Keychain) import2fas(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("reading import file: %v", err)
	}

	var export TwoFASExport
	if err := json.Unmarshal(data, &export); err != nil {
		log.Fatalf("parsing 2fas JSON: %v", err)
	}

	imported := 0
	var newEntries []string

	for _, service := range export.Services {
		name := c.getServiceName(service)
		if name == "" {
			log.Printf("skipping service with no name")
			continue
		}

		// Check if key already exists
		if _, exists := c.keys[name]; exists {
			log.Printf("skipping %q: already exists", name)
			continue
		}

		// Validate and format the secret key
		secret := strings.Map(noSpace, service.Secret)
		secret += strings.Repeat("=", -len(secret)&7) // pad to 8 bytes
		if _, err := decodeKey(secret); err != nil {
			log.Printf("skipping %q: invalid secret key: %v", name, err)
			continue
		}

		// Default to 6 digits if not specified
		digits := service.OTP.Digits
		if digits == 0 {
			digits = 6
		}

		// Build the key line
		line := fmt.Sprintf("%s %d %s", name, digits, secret)

		// Add counter for HOTP
		if service.OTP.TokenType == "HOTP" {
			line += " " + strings.Repeat("0", 20)
		}

		newEntries = append(newEntries, line)
		imported++
		fmt.Printf("imported: %s\n", name)
	}

	if imported > 0 {
		// Add new entries to keychain map
		for _, line := range newEntries {
			parts := strings.Split(line, " ")
			if len(parts) >= 3 {
				c.keys[parts[0]] = Key{} // Temporary entry for sorting
			}
		}

		// Rewrite entire file in sorted order
		if err := c.rewriteSorted(newEntries); err != nil {
			log.Fatalf("rewriting keychain: %v", err)
		}
	}

	fmt.Printf("\nSuccessfully imported %d key(s)\n", imported)
}

// getServiceName extracts the best available name for a service
func (c *Keychain) getServiceName(service TwoFASService) string {
	var serviceName, account string

	// Get service name and replace spaces with underscores
	if service.Name != "" {
		serviceName = strings.ReplaceAll(service.Name, " ", "_")
	} else if service.OTP.Issuer != "" {
		serviceName = strings.ReplaceAll(service.OTP.Issuer, " ", "_")
	}

	// Get account (keep spaces in account names)
	if service.OTP.Account != "" {
		account = service.OTP.Account
	} else if service.OTP.Label != "" {
		account = service.OTP.Label
	}

	// Build name in format: serviceName/account
	if serviceName != "" && account != "" {
		return serviceName + "/" + account
	}
	if serviceName != "" {
		return serviceName
	}
	if account != "" {
		return account
	}

	return ""
}
