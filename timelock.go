package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

type chainfileLink struct {
	PlaintextSeed []byte `json:plaintext_seed`
	Hash          []byte `json:plaintext_seed`
}

type lockfileLink struct {
	EncyptedSeed []byte `json:seed`
	VerifyHash   []byte `json:verify` // Hash of hash.
}

type lockfileFormat struct {
	Meta  map[string]string
	Chain []lockfileLink
}

type chainfileFormat struct {
	Meta  map[string]string
	Chain []chainfileLink
}

////////////////

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "No command specified.\n")
		return
	}
	cmd := os.Args[1]
	os.Args = append(os.Args[0:1], os.Args[2:]...)

	switch cmd {
	case "benchmark":
		rounds := flag.Int("rounds", 100000, "Number of hashes to use in benchmark")
		flag.Parse()
		_benchmark(*rounds)
	case "work":
		rounds := flag.Int("rounds", 100000, "Number of hashes to use in benchmark")
		links := flag.Int("j", 1, "Number of links to compute, e.g. threads")
		flag.Parse()
		_work(*links, *rounds)
	case "concat":
		_concat(os.Args[1:])
	case "lock":
		_lock()
	case "unlock":
		_unlock()

	default:
		fmt.Printf("Unknown command: %s\n", cmd)
	}
}

func _benchmark(rounds int) {
	fmt.Fprintf(os.Stderr, "Benchmarking hasher...\n")
	start := time.Now()
	hashChainRounds(rounds, randomBytes(64))
	duration := time.Now().Sub(start).Seconds()
	hashesPerSecond := float64(rounds) / duration
	fmt.Fprintf(os.Stderr, "%d hashes in %f seconds; %.0f hashes per second\n",
		rounds, duration, hashesPerSecond)
}

func _work(links int, rounds int) {
	fmt.Fprintf(os.Stderr, "Creating a chainfile with %d links, each of %d rounds...\n",
		links, rounds)
	chain := make([]chainfileLink, 0)
	for j := 0; j < links; j++ {
		seed := randomBytes(64)
		hash := hashChainRounds(rounds, seed)
		chain = append(chain, chainfileLink{PlaintextSeed: seed, Hash: hash})
		fmt.Fprintf(os.Stderr, "Computing link %d\n", j)
	}

	if err := writeChainfile(os.Stdout, chain); err != nil {
		panic(err)
	}
}

func _concat(filePaths []string) {
	fmt.Fprintf(os.Stderr, "Merging %d chainfiles into one chainfile...\n",
		len(filePaths))
	mergedChain := make([]chainfileLink, 0)
	for _, path := range filePaths {
		f, err := os.Open(path)
		if err != nil {
			panic(err)
		}

		chainfile := &chainfileFormat{}
		json.NewDecoder(f).Decode(chainfile)

		for _, chainLink := range chainfile.Chain {
			mergedChain = append(mergedChain, chainLink)
		}
	}
	if err := writeChainfile(os.Stdout, mergedChain); err != nil {
		panic(err)
	}
}

func _lock() {
	fmt.Fprintf(os.Stderr, "Converting chainfile to lockfile...\n")

	chainfile := &chainfileFormat{}
	json.NewDecoder(os.Stdin).Decode(chainfile)
	lockedChain := transformChainFileToLockFile(chainfile.Chain)
	if err := writeLockfile(os.Stdout, lockedChain); err != nil {
		panic(err)
	}
}

func _unlock() {
	lockfile := &lockfileFormat{}
	json.NewDecoder(os.Stdin).Decode(lockfile)
	fmt.Fprintf(os.Stderr, "Unlocking lockfile with %d links...\n", len(lockfile.Chain))

	var previousHash []byte = nil
	for i, chainLink := range lockfile.Chain {
		var plaintextSeed []byte
		if previousHash == nil {
			// This is the first block and thus the EncyptedSeed isn't encrypted
			plaintextSeed = chainLink.EncyptedSeed
		} else {
			// First 32 bytes of hash are the key
			block, err := aes.NewCipher(previousHash[0:32])
			if err != nil {
				panic(err)
			}

			// Next 16 bytes are the IV
			mode := cipher.NewCBCDecrypter(block, previousHash[32:32+aes.BlockSize])

			// Decrypt
			plaintextSeed = make([]byte, len(chainLink.EncyptedSeed))
			mode.CryptBlocks(plaintextSeed, chainLink.EncyptedSeed)
		}

		fmt.Fprintf(os.Stderr, "Unlocking link #%d\n", i)
		previousHash = hashChainVerification(plaintextSeed, chainLink.VerifyHash)
	}

	fmt.Fprintf(os.Stderr, "Unlock successful. Final hash: %s\n",
		base64.URLEncoding.EncodeToString(previousHash))
	fmt.Fprintf(os.Stdout, "%s", base64.URLEncoding.EncodeToString(previousHash))
}

func writeChainfile(w io.Writer, chain []chainfileLink) error {
	jsonEncoder := json.NewEncoder(w)
	err := jsonEncoder.Encode(chainfileFormat{
		Meta: map[string]string{
			"version":        "1",
			"hash_algorithm": "sha512-a",
		},
		Chain: chain,
	})

	return err
}

func transformChainFileToLockFile(chain []chainfileLink) []lockfileLink {
	lockedChain := make([]lockfileLink, len(chain))

	for i := 0; i < len(chain); i++ {
		var encryptedSeed []byte

		if i == 0 {
			// First link's seed isn't encrypted
			encryptedSeed = chain[i].PlaintextSeed
		} else {
			// Other links are encrypted with previous link's hash.
			previousHash := chain[i-1].Hash

			// First 32 bytes of hash are the key
			block, err := aes.NewCipher(previousHash[0:32])
			if err != nil {
				panic(err)
			}

			// Next 16 bytes are the IV
			mode := cipher.NewCBCEncrypter(block, previousHash[32:32+aes.BlockSize])

			// Encrypt
			encryptedSeed = make([]byte, len(chain[i].PlaintextSeed))
			mode.CryptBlocks(encryptedSeed, chain[i].PlaintextSeed)
		}

		// Verification hash
		hasher := sha512.New()
		hasher.Write(chain[i].Hash)
		verification_hash := hasher.Sum(nil)

		lockedChain[i] = lockfileLink{
			EncyptedSeed: encryptedSeed,
			VerifyHash:   verification_hash,
		}
	}
	return lockedChain
}

func writeLockfile(w io.Writer, chain []lockfileLink) error {
	jsonEncoder := json.NewEncoder(w)
	err := jsonEncoder.Encode(lockfileFormat{
		Meta: map[string]string{
			"version":          "1",
			"hash_algorithm":   "sha512-a",
			"cipher_algorithm": "aes-256-cbc",
		},
		Chain: chain,
	})

	return err
}

func hashChainRounds(rounds int, seed []byte) []byte {
	for i := 0; i < rounds; i++ {
		hasher := sha512.New()
		hasher.Write(seed)
		seed = hasher.Sum(nil)
	}
	return seed
}

func hashChainVerification(seed []byte, verify []byte) []byte {
	for {
		hasher := sha512.New()
		hasher.Write(seed)
		sum := hasher.Sum(nil)
		if bytes.Equal(sum, verify) {
			return seed
		}
		seed = sum
	}
}

func randomBytes(c int) []byte {
	b := make([]byte, c)
	n, err := io.ReadFull(rand.Reader, b)
	if n != len(b) || err != nil {
		fmt.Println("error:", err)
		return nil
	}
	return b
}

func join(args []string) {
	fmt.Printf("")
}
