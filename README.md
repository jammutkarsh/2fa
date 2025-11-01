# 2fa is a two-factor authentication agent

## Table of Contents

- [Supported Imports](#supported-imports)
- [Usage](#usage)
- [Example](#example)
- [Importing from 2FAS](#importing-from-2fas)
- [Fuzzy Matching](#fuzzy-matching)

`2fa` is a command-line tool for managing two-factor authentication keys

## Supported Imports

- [2FAS](https://2fas.com/)

Raise an issue to request support for Authenticator Apps.

## Usage

```bash
go install github.com/jammutkarsh/2fa@latest

2fa -add [-7] [-8] [-hotp] name
2fa -list
2fa name # Uses fuzzy matching and automatically copies to clipboard
2fa -import 2fas <file>
```

`2fa -add name` adds a new key to the 2fa keychain with the given name. It
prints a prompt to standard error and reads a two-factor key from standard
input. Two-factor keys are short case-insensitive strings of letters A-Z and
digits 2-7.

By default, the new key generates time-based (TOTP) authentication codes; the
`-hotp` flag makes the new key generate counter-based (HOTP) codes instead.

By default, the new key generates 6-digit codes; the `-7` and `-8` flags select
7- and 8-digit codes instead.

`2fa -list` lists the names of all the keys in the keychain.

`2fa name` prints a two-factor authentication code from the key with the
given name and **automatically copies it to the system clipboard**. The name
supports fuzzy matching - if the search matches exactly one key, that code
will be displayed and copied. If multiple keys match, all matching codes
will be listed (clipboard is not used for multiple matches).

`2fa -import 2fas <file>` imports keys from a 2FAS JSON export file. This
allows bulk import of all your 2FA keys. Keys that already exist will be
skipped.

With no arguments, `2fa` prints two-factor authentication codes from all
known time-based keys.

The default time-based authentication codes are derived from a hash of the
key and the current time, so it is important that the system clock have at
least one-minute accuracy.

The keychain is stored unencrypted in the text file `$HOME/.2fa`.

## Example

During GitHub 2FA setup, at the "Scan this barcode with your app" step,
click the "enter this text code instead" link. A window pops up showing
"your two-factor secret," a short string of letters and digits.

Add it to 2fa under the name github, typing the secret at the prompt:

    $ 2fa -add github
    2fa key for github: nzxxiidbebvwk6jb
    $

Then whenever GitHub prompts for a 2FA code, run 2fa to obtain one:

    $ 2fa github
    268346
    $

The code is automatically copied to your clipboard! Just paste it.

Or use fuzzy matching to type less:

    $ 2fa git
    268346
    $

Or to see all codes:

    $ 2fa
    268346 github
    123456 google
    $

## Importing from 2FAS

Export your 2FAS data to a JSON file, then import it:

    $ 2fa -import 2fas export.json
    imported: Discord
    imported: GitHub
    imported: Google
    
    Successfully imported 3 key(s)
    $

## Fuzzy Matching

The tool supports fuzzy matching for key names, making it easier to find keys:

    $ 2fa gthb
    268346
    $
    
If multiple keys match, all will be displayed:

    $ 2fa go
    multiple matches found for "go":
    123456  google
    789012  gojek
    $
