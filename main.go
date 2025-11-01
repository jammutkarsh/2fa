// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// 2fa is a two-factor authentication agent.
//
// Usage:
//
//	2fa -add [-7] [-8] [-hotp] name
//	2fa -list
//	2fa [-clip] name
//
// “2fa -add name” adds a new key to the 2fa keychain with the given name.
// It prints a prompt to standard error and reads a two-factor key from standard input.
// Two-factor keys are short case-insensitive strings of letters A-Z and digits 2-7.
//
// By default the new key generates time-based (TOTP) authentication codes;
// the -hotp flag makes the new key generate counter-based (HOTP) codes instead.
//
// By default the new key generates 6-digit codes; the -7 and -8 flags select
// 7- and 8-digit codes instead.
//
// “2fa -list” lists the names of all the keys in the keychain.
//
// “2fa name” prints a two-factor authentication code from the key with the
// given name. If “-clip” is specified, 2fa also copies the code to the system
// clipboard.
//
// With no arguments, 2fa prints two-factor authentication codes from all
// known time-based keys.
//
// The default time-based authentication codes are derived from a hash of
// the key and the current time, so it is important that the system clock have
// at least one-minute accuracy.
//
// The keychain is stored unencrypted in the text file $HOME/.2fa.
//
// # Example
//
// During GitHub 2FA setup, at the “Scan this barcode with your app” step,
// click the “enter this text code instead” link. A window pops up showing
// “your two-factor secret,” a short string of letters and digits.
//
// Add it to 2fa under the name github, typing the secret at the prompt:
//
//	$ 2fa -add github
//	2fa key for github: nzxxiidbebvwk6jb
//	$
//
// Then whenever GitHub prompts for a 2FA code, run 2fa to obtain one:
//
//	$ 2fa github
//	268346
//	$
//
// Or to type less:
//
//	$ 2fa
//	268346	github
//	$
package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/atotto/clipboard"
	"github.com/lithammer/fuzzysearch/fuzzy"
)

var (
	flagAdd    = flag.Bool("add", false, "add a key")
	flagList   = flag.Bool("list", false, "list keys")
	flagHotp   = flag.Bool("hotp", false, "add key as HOTP (counter-based) key")
	flag7      = flag.Bool("7", false, "generate 7-digit code")
	flag8      = flag.Bool("8", false, "generate 8-digit code")
	flagImport = flag.Bool("import", false, "import keys from file")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "\t2fa -add [-7] [-8] [-hotp] keyname\n")
	fmt.Fprintf(os.Stderr, "\t2fa -list\n")
	fmt.Fprintf(os.Stderr, "\t2fa keyname\n")
	fmt.Fprintf(os.Stderr, "\t2fa -import 2fas <file>\n")
	os.Exit(2)
}

func main() {
	log.SetPrefix("2fa: ")
	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()

	k := readKeychain(filepath.Join(os.Getenv("HOME"), ".2fa"))

	if *flagList {
		if flag.NArg() != 0 {
			usage()
		}
		k.list()
		return
	}
	if *flagImport {
		if flag.NArg() != 2 {
			usage()
		}
		format := flag.Arg(0)
		file := flag.Arg(1)
		if format != "2fas" {
			log.Fatalf("unsupported import format: %s", format)
		}
		k.import2fas(file)
		return
	}
	if flag.NArg() == 0 && !*flagAdd {
		k.showAll()
		return
	}
	if flag.NArg() != 1 {
		usage()
	}
	name := flag.Arg(0)
	if *flagAdd {
		k.add(name)
		return
	}
	k.show(name)
}

type Keychain struct {
	file string
	data []byte
	keys map[string]Key
}

type Key struct {
	raw    []byte
	digits int
	offset int // offset of counter
}

const counterLen = 20

// fuzzyMatch finds keys that fuzzy match the search string
func (c *Keychain) fuzzyMatch(search string) []string {
	var allNames []string
	for name := range c.keys {
		allNames = append(allNames, name)
	}

	// Convert search to lowercase for case-insensitive matching
	search = strings.ToLower(search)
	
	// Create lowercase version of all names for matching
	lowerNames := make([]string, len(allNames))
	for i, name := range allNames {
		lowerNames[i] = strings.ToLower(name)
	}

	// First try fuzzy.RankFind for fuzzy matches on lowercase names
	ranks := fuzzy.RankFind(search, lowerNames)

	if len(ranks) > 0 {
		var matches []string
		for _, rank := range ranks {
			// Find the original name (with correct case) using the index
			for i, lowerName := range lowerNames {
				if lowerName == rank.Target {
					matches = append(matches, allNames[i])
					break
				}
			}
		}
		return matches
	}

	// Fallback to simple substring matching if no fuzzy matches
	var matches []string
	for name := range c.keys {
		if strings.Contains(strings.ToLower(name), search) {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)
	return matches
}

func readKeychain(file string) *Keychain {
	c := &Keychain{
		file: file,
		keys: make(map[string]Key),
	}
	data, err := ioutil.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return c
		}
		log.Fatal(err)
	}
	c.data = data

	lines := bytes.SplitAfter(data, []byte("\n"))
	offset := 0
	for i, line := range lines {
		lineno := i + 1
		offset += len(line)
		f := bytes.Split(bytes.TrimSuffix(line, []byte("\n")), []byte(" "))
		if len(f) == 1 && len(f[0]) == 0 {
			continue
		}
		// Changed: Handle names with spaces by looking for digit and secret pattern
		// Format: name(s) digit secret [counter]
		// Find the digit position (should be '6', '7', or '8')
		digitPos := -1
		for i := len(f) - 1; i >= 1; i-- {
			if len(f[i]) == 1 && '6' <= f[i][0] && f[i][0] <= '8' {
				// Check if next field looks like a base32 secret
				if i+1 < len(f) && len(f[i+1]) > 0 {
					digitPos = i
					break
				}
			}
		}

		if digitPos >= 1 && digitPos+1 < len(f) {
			var k Key
			// Name is everything before digitPos, joined with spaces
			nameParts := f[0:digitPos]
			name := string(bytes.Join(nameParts, []byte(" ")))
			k.digits = int(f[digitPos][0] - '0')
			raw, err := decodeKey(string(f[digitPos+1]))
			if err == nil {
				k.raw = raw
				if len(f) == digitPos+2 {
					c.keys[name] = k
					continue
				}
				if len(f) == digitPos+3 && len(f[digitPos+2]) == counterLen {
					_, err := strconv.ParseUint(string(f[digitPos+2]), 10, 64)
					if err == nil {
						// Valid counter.
						k.offset = offset - counterLen
						if line[len(line)-1] == '\n' {
							k.offset--
						}
						c.keys[name] = k
						continue
					}
				}
			}
		}
		log.Printf("%s:%d: malformed key", c.file, lineno)
	}
	return c
}

func (c *Keychain) list() {
	var names []string
	for name := range c.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name)
	}
}

func noSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}

func (c *Keychain) add(name string) {
	size := 6
	if *flag7 {
		size = 7
		if *flag8 {
			log.Fatalf("cannot use -7 and -8 together")
		}
	} else if *flag8 {
		size = 8
	}

	fmt.Fprintf(os.Stderr, "2fa key for %s: ", name)
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error reading key: %v", err)
	}
	text = strings.Map(noSpace, text)
	text += strings.Repeat("=", -len(text)&7) // pad to 8 bytes
	if _, err := decodeKey(text); err != nil {
		log.Fatalf("invalid key: %v", err)
	}

	line := fmt.Sprintf("%s %d %s", name, size, text)
	if *flagHotp {
		line += " " + strings.Repeat("0", 20)
	}

	// Add to keychain map
	c.keys[name] = Key{} // Temporary entry for sorting

	// Rewrite entire file in sorted order
	if err := c.rewriteSorted([]string{line}); err != nil {
		log.Fatalf("adding key: %v", err)
	}
}

// rewriteSorted rewrites the entire keychain file in sorted order
func (c *Keychain) rewriteSorted(newEntries []string) error {
	// Read all existing lines
	var existingLines []string
	if len(c.data) > 0 {
		lines := bytes.Split(bytes.TrimSuffix(c.data, []byte("\n")), []byte("\n"))
		for _, line := range lines {
			if len(line) > 0 {
				existingLines = append(existingLines, string(line))
			}
		}
	}

	// Combine existing and new entries
	allLines := append(existingLines, newEntries...)

	// Sort all lines by name (first field)
	sort.Slice(allLines, func(i, j int) bool {
		partsI := strings.Split(allLines[i], " ")
		partsJ := strings.Split(allLines[j], " ")
		if len(partsI) > 0 && len(partsJ) > 0 {
			return strings.ToLower(partsI[0]) < strings.ToLower(partsJ[0])
		}
		return allLines[i] < allLines[j]
	})

	// Write sorted entries to file
	f, err := os.OpenFile(c.file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("opening keychain: %v", err)
	}
	defer f.Close()
	f.Chmod(0600)

	for _, line := range allLines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("writing keychain: %v", err)
		}
	}

	return nil
}

func (c *Keychain) code(name string) string {
	k, ok := c.keys[name]
	if !ok {
		log.Fatalf("no such key %q", name)
	}
	var code int
	if k.offset != 0 {
		n, err := strconv.ParseUint(string(c.data[k.offset:k.offset+counterLen]), 10, 64)
		if err != nil {
			log.Fatalf("malformed key counter for %q (%q)", name, c.data[k.offset:k.offset+counterLen])
		}
		n++
		code = hotp(k.raw, n, k.digits)
		f, err := os.OpenFile(c.file, os.O_RDWR, 0600)
		if err != nil {
			log.Fatalf("opening keychain: %v", err)
		}
		if _, err := f.WriteAt([]byte(fmt.Sprintf("%0*d", counterLen, n)), int64(k.offset)); err != nil {
			log.Fatalf("updating keychain: %v", err)
		}
		if err := f.Close(); err != nil {
			log.Fatalf("updating keychain: %v", err)
		}
	} else {
		// Time-based key.
		code = totp(k.raw, time.Now(), k.digits)
	}
	return fmt.Sprintf("%0*d", k.digits, code)
}

func (c *Keychain) show(name string) {
	// Try exact match first
	if _, ok := c.keys[name]; ok {
		code := c.code(name)
		clipboard.WriteAll(code)
		fmt.Printf("copied\t%s\t%s\n", code, name)
		return
	}

	// Try fuzzy match
	matches := c.fuzzyMatch(name)
	if len(matches) == 0 {
		log.Fatalf("no such key %q", name)
	}
	if len(matches) == 1 {
		// Single match found
		matchName := matches[0]
		code := c.code(matchName)
		clipboard.WriteAll(code)
		fmt.Printf("copied\t%s\t%s\n", code, matchName)
		return
	}

	// Multiple matches - show all
	fmt.Fprintf(os.Stderr, "multiple matches found for %q:\n", name)
	max := 0
	for _, match := range matches {
		if k := c.keys[match]; max < k.digits {
			max = k.digits
		}
	}
	for _, match := range matches {
		code := c.code(match)
		fmt.Printf("%-*s\t%s\n", max, code, match)
	}
	os.Exit(1)
}

func (c *Keychain) showAll() {
	var names []string
	max := 0
	for name, k := range c.keys {
		names = append(names, name)
		if max < k.digits {
			max = k.digits
		}
	}
	sort.Strings(names)
	for _, name := range names {
		k := c.keys[name]
		code := strings.Repeat("-", k.digits)
		if k.offset == 0 {
			code = c.code(name)
		}
		fmt.Printf("%-*s\t%s\n", max, code, name)
	}
}

func decodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}

func hotp(key []byte, counter uint64, digits int) int {
	h := hmac.New(sha1.New, key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func totp(key []byte, t time.Time, digits int) int {
	return hotp(key, uint64(t.UnixNano())/30e9, digits)
}
