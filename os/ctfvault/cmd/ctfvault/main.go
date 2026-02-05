package main

import (
    "os"

    "ctfvault/internal/cli"
)

func main() {
    os.Exit(cli.Run("ctfvault", os.Args[1:]))
}

