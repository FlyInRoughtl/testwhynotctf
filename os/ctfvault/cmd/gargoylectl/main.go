package main

import (
	"os"

	"gargoyle/internal/cli"
)

func main() {
	os.Exit(cli.Run("gargoylectl", os.Args[1:]))
}
