package main

// check sha sum 
/*
// roughly equivalent of the following bash script, except if $3 interpret as file does not exist then it's assumed to be the expected shasum
match_sha(){
  target=$1
  alg=${2:-256}
  shafile=$1.$alg
  computed=$(shasum -a $alg $target)
  expectedfile=$target.sha"$alg"
  found=${3:-$expectedfile} 
  echo $expectedfile
  cat $expectedfile
  echo $computed
}
*/

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
)

func makeHasher(alg string) hash.Hash {
	var hasher hash.Hash
	switch alg {
	case "256":
		hasher = sha256.New()
	case "512":
		hasher = sha512.New()
	default:
		panic(fmt.Sprintf("unsupported: sha%s\n", alg))
	}
	return hasher
}

func matchSHA(target string, alg string, found string) {
	if alg == "" {
		alg = "256"
	}
	expectedSHAFile := fmt.Sprintf("%s.sha%s", target, alg)
	if found != "" {
		expectedSHAFile = found
	}

	hasher := makeHasher(alg)
	targetFile, err := os.Open(target)
	if err != nil {
		fmt.Printf("'%s' not found\n", target)
		return
	}
	defer targetFile.Close()

	if _, err := io.Copy(hasher, targetFile); err != nil {
		fmt.Printf("error reading '%s': %v\n", target, err)
		return
	}

	computedDigest := hex.EncodeToString(hasher.Sum(nil))
	computed := fmt.Sprintf("%s  %s [computed]", computedDigest, target)

	sha := ""
	if _, err := os.Stat(expectedSHAFile); err == nil {
		content, err := os.ReadFile(expectedSHAFile)
		if err == nil {
			sha = strings.TrimSpace(string(content))
		}
	} else {
		sha = found
	}

	fmt.Println(computed)
	fmt.Println(sha, expectedSHAFile)
	if sha != "" {
		fmt.Println(computedDigest == sha)
	}
}

func orDefault(args []string, index int, defaultValue string) string {
	if index < len(args) {
		return args[index]
	} else {
		return defaultValue
	}
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("\n\tmatchsha $file [alg] [found]")
		return
	}

	target := args[0]
	alg := orDefault(args, 1, "256")
	found := orDefault(args, 2, "")

	matchSHA(target, alg, found)
}
