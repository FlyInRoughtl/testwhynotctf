package main

import (
	"os"

	"gargoyle/internal/cli"
)

func main() {
	os.Exit(cli.Run("gargoyle", os.Args[1:]))
}
