// Sandtrap — behavioral supply chain scanner for npm and PyPI packages.
//
// It inspects package tarballs and registry metadata for the patterns used
// by real-world supply chain attacks (Shai-Hulud, Mini Shai-Hulud, axios
// compromise, etc.): install-script hooks, obfuscated payloads, credential
// harvesting and exfiltration primitives.
package main

import (
	"os"

	"github.com/JAugusto42/sandtrap/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
