package main

import (
    "os"

    "ctfvault/internal/cli"
)

func main() {
    os.Exit(cli.Run("ctfvaultctl", os.Args[1:]))
}

