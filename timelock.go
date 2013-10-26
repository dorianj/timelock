package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
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

func main() {
	fmt.Printf("Benchmarking hasher...\n")
	start := time.Now()
	rounds := 800000
	hashChainRounds(rounds, randomBytes(64))
	duration := time.Now().Sub(start).Seconds()
	hashesPerSecond := float64(rounds) / duration
	fmt.Printf("Took %f seconds for %d hashes (%.0f hashes per second)\n",
		duration, rounds, hashesPerSecond)

	chainfileCount := 6
	fmt.Printf("Creating %d chainfiles...\n", chainfileCount)

	for j := 0; j < chainfileCount; j++ {
		seed := randomBytes(64)
		hash := hashChainRounds(rounds, seed)

		f, err := os.Create(fmt.Sprintf("tmp_chainfile%d.json", j))
		if err != nil {
			panic(err)
		}

		link := chainfileLink{PlaintextSeed: seed, Hash: hash}
		if err := writeChainfile(f, []chainfileLink{link}); err != nil {
			panic(err)
		}
	}

	fmt.Printf("Merging into one chainfile...\n")
	mergedChain := make([]chainfileLink, 0)
	for j := 0; j < chainfileCount; j++ {
		f, err := os.Open(fmt.Sprintf("tmp_chainfile%d.json", j))
		if err != nil {
			panic(err)
		}

		chainfile := &chainfileFormat{}
		json.NewDecoder(f).Decode(chainfile)

		for _, chainLink := range chainfile.Chain {
			mergedChain = append(mergedChain, chainLink)
		}

		os.Remove(fmt.Sprintf("tmp_chainfile%d.json", j))
	}

	fmt.Printf("Merged chainfile has %d links. Final hash: %s\n",
		len(mergedChain), base64.URLEncoding.EncodeToString(mergedChain[len(mergedChain)-1].Hash))

	fmt.Printf("Converting chainfile to lockfile...\n")
	lockedChain := transformChainFileToLockFile(mergedChain)
	fmt.Printf("Locked chain has %d links\n", len(lockedChain))

	fmt.Printf("Writing out the lockfile...\n")
	outputFile, err := os.Create("lockfile.json")
	if err != nil {
		panic(err)
	}

	if err := writeLockfile(outputFile, lockedChain); err != nil {
		panic(err)
	}

	fmt.Printf("\nUnlocking the lockfile...\n")
	f, err := os.Open("lockfile.json")
	if err != nil {
		panic(err)
	}

	lockfile := &lockfileFormat{}
	json.NewDecoder(f).Decode(lockfile)

	var previousHash []byte = nil
	for _, chainLink := range lockfile.Chain {
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

		previousHash = hashChainVerification(plaintextSeed, chainLink.VerifyHash)
	}

	fmt.Printf("Unlock successful. Final hash: %s\n",
		base64.URLEncoding.EncodeToString(previousHash))

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
