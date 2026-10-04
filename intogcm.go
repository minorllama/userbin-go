package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

func createGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}

func readInputData(inputFile string) ([]byte, error) {
	if inputFile == "-" || inputFile == "" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(inputFile)
}

func decryptData(inputData []byte, key []byte) ([]byte, error) {
	gcm, err := createGCM(key)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(inputData) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, actualCiphertext := inputData[:nonceSize], inputData[nonceSize:]
	return gcm.Open(nil, nonce, actualCiphertext, nil)
}

func encryptData(inputData []byte, key []byte) ([]byte, error) {
	gcm, err := createGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, inputData, nil), nil
}

// readKeyFile verifies strict user-only read permissions (0400 or 0600) and decodes base64 content.
func readKeyFile(filename string) ([]byte, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("[stat failed for key file: %w]", err)
	}

	// ensure group and other permissions are 0 (e.g., 0400 or 0600)
	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		return nil, fmt.Errorf("[insecure key file permissions (%04o); file must be read-only to user (e.g., 0400 or 0600)]", mode)
	}

	encodedData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	trimmed := strings.TrimSpace(string(encodedData))
	decodedBytes, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 key: %w", err)
	}

	return decodedBytes, nil
}

// loadKey evaluates the string passed from an argument or environment variable.
func loadKey(keyInput string) ([]byte, error) {
	// if input points to a file scheme "file:///path/to/key"
	if strings.HasPrefix(keyInput, "file://") {
		filePath := strings.TrimPrefix(keyInput, "file://")
		return readKeyFile(filePath)
	}

	// try reading directly as a base64 string
	trimmed := strings.TrimSpace(keyInput)
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil && len(decoded) > 0 {
		return decoded, nil
	}

	// if it's a direct file path without the file:// prefix
	if fileExists(keyInput) {
		return readKeyFile(keyInput)
	}

	return nil, fmt.Errorf("invalid key specification: string is not valid base64 nor an accessible file")
}

func bytesToBase64File(filename string, data []byte) error {
	encodedString := base64.StdEncoding.EncodeToString(data)
	// write with 0600 permissions (read/write only by owner)
	return os.WriteFile(filename, []byte(encodedString), 0600)
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func main() {
	args := os.Args[1:]


	if args[0] == "-e:b64" && len(args) == 2 {
		fmt.Printf("%s", base64.StdEncoding.EncodeToString([]byte(args[1])))
		os.Exit(0)
	} else if args[0] == "-d:b64" && len(args) == 2 {
		bytes, err := base64.StdEncoding.DecodeString(args[1])
		if err == nil {
			fmt.Printf("%s", string(bytes))
			os.Exit(0)
		} else {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if len(args) < 3 {
		fmt.Println("\n\tusage: go run main.go <key|file://path|ENV_VAR> <infile|-> <op:outfile>")
		fmt.Println("\n\t\texample: go run main.go KEY_ENV - -e:out.enc")
		detailedExample :=`
			$ echo "hello" > hello.txt
			$ ./intogcm -e:b64 A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6
			QTFiMkMzZDRFNWY2RzdoOEk5ajBLMWwyTTNuNE81cDY=
			$ V="QTFiMkMzZDRFNWY2RzdoOEk5ajBLMWwyTTNuNE81cDY=" ./intogcm V ./hello.txt -e:hello.e
			ok
			$ V="QTFiMkMzZDRFNWY2RzdoOEk5ajBLMWwyTTNuNE81cDY=" ./intogcm V ./hello.e -d:hello.o
			ok
			$ cat hello.o
			hello`
		fmt.Println(detailedExample)
		os.Exit(1)
	}


	keyArg := args[0]
	infile := args[1]
	opAndOutfile := strings.SplitN(args[2], ":", 2)

	if len(opAndOutfile) < 2 {
		fmt.Println("Invalid operation format. Expected -e:outfile or -d:outfile")
		os.Exit(1)
	}

	op := opAndOutfile[0]
	outfile := opAndOutfile[1]

	if fileExists(outfile) {
		fmt.Printf("[file exists: %s]\n", outfile)
		os.Exit(1)
	}

	// resolve key: directly from arg, or from environment variable matching arg name
	var rawKeySpec string
	if envVal, exists := os.LookupEnv(keyArg); exists {
		rawKeySpec = envVal
	} else {
		rawKeySpec = keyArg
	}

	key, err := loadKey(rawKeySpec)
	if err != nil {
		fmt.Printf("[key error: %v]\n", err)
		os.Exit(1)
	}

	inputData, err := readInputData(infile)
	if err != nil {
		fmt.Printf("[input error: %v]\n", err)
		os.Exit(1)
	}

	var outputData []byte
	switch op {
	case "-e":
		outputData, err = encryptData(inputData, key)
	case "-d":
		outputData, err = decryptData(inputData, key)

	default:
		fmt.Printf("Unknown operation: %s\n", op)
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("[error[%s]: %v]\n", op, err)
		os.Exit(1)
	}

	if err := os.WriteFile(outfile, outputData, 0644); err != nil {
		fmt.Printf("[write error: %v]\n", err)
		os.Exit(1)
	}

	fmt.Println("ok")
}
