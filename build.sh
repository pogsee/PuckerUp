#!/bin/bash

# This script compiles the Go applications and prepares them for distribution.

echo "--- Starting PuckerUp Build ---"

# Set the Go build flags to create a static binary for Linux.
# This makes it highly portable across different Linux distributions.
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

# Create a distribution directory to hold the final files.
echo "Creating distribution directory..."
rm -rf ./app
mkdir ./app

# Compile the main server application.
echo "Compiling main server..."
go build -o ./app/puckerup ./main.go

# Compile the password generator utility.
echo "Compiling password generator..."
go build -o ./app/puckerup-passwd ./generate-password.go

# Copy the necessary web files.
echo "Copying web files..."
cp ./index.html ./app/
cp ./login.html ./app/

echo "--- Build Complete ---"
echo "Distribution files are ready in the 'app' directory."
