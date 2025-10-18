package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand" // Aliased to avoid conflict with crypto/rand
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Simple word lists embedded in the binary.
var adjectives = []string{"green", "blue", "fast", "angry", "happy", "sleepy", "clever", "shiny", "brave", "calm", "eager", "gentle", "jolly", "kind", "lively", "proud", "silly", "witty", "zany", "mocha"}
var nouns = []string{"whales", "dogs", "cats", "texan", "puck", "server", "code", "tree", "river", "cloud", "star", "moon", "sun", "leaf", "ship", "frog", "lake", "stone", "bird", "inside"}
var verbs = []string{"fly", "run", "jump", "swim", "read", "write", "think", "dream", "build", "drive", "eat", "sleep", "laugh", "dance", "sing", "explore", "create", "inspire", "win", "glow"}

func getRandomWord(wordList []string) string {
	// This uses the crypto/rand package for secure random selection.
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(wordList))))
	if err != nil {
		log.Fatal("Could not generate random number:", err)
	}
	return wordList[n.Int64()]
}

func main() {
	// Seed the math/rand package for the number generation.
	// We use the 'mrand' alias here.
	mrand.Seed(time.Now().UnixNano())

	// 1. Generate the human-readable password
	// We use the 'mrand' alias here.
	randomNumber := mrand.Intn(900) + 100 // Generate a number between 100-999
	password := fmt.Sprintf("%s_%s_%s_%d", getRandomWord(adjectives), getRandomWord(nouns), getRandomWord(verbs), randomNumber)

	// 2. Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Failed to hash password:", err)
	}

	// 3. Define the path for the password file
	// Assumes it's being run relative to the main app, or that /srv/puckserver exists.
	passwordFilePath := "/srv/puckserver/.puckerup_password"
	dir := filepath.Dir(passwordFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("Failed to create directory %s: %v", dir, err)
	}

	// 4. Write the HASH to the file
	err = os.WriteFile(passwordFilePath, hashedPassword, 0600)
	if err != nil {
		log.Fatal("Failed to write password file:", err)
	}

	// 5. Print the PLAIN TEXT password to standard output for the install script
	fmt.Print(password)
}

