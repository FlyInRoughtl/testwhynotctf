package dsl

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

type CommandFunc func(*Context, []string) error

type Engine struct {
	commands map[string]CommandFunc
}

type Context struct {
	Vars map[string]string
	Out  func(string)
	Err  func(string)
}

func NewEngine() *Engine {
	return &Engine{commands: make(map[string]CommandFunc)}
}

func (e *Engine) Register(name string, fn CommandFunc) {
	e.commands[strings.ToLower(name)] = fn
}

func (e *Engine) RunFile(ctx *Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		args := splitArgs(line)
		if len(args) == 0 {
			continue
		}
		cmd := strings.ToLower(args[0])
		fn, ok := e.commands[cmd]
		if !ok {
			return fmt.Errorf("unknown command at line %d: %s", lineNo, cmd)
		}
		if err := fn(ctx, args[1:]); err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
	}
	return scanner.Err()
}

func splitArgs(line string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	esc := false
	for _, r := range line {
		if esc {
			b.WriteRune(r)
			esc = false
			continue
		}
		switch r {
		case '\\':
			esc = true
		case '"':
			inQuote = !inQuote
		default:
			if !inQuote && (r == ' ' || r == '\t') {
				if b.Len() > 0 {
					out = append(out, b.String())
					b.Reset()
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	if inQuote {
		return out
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func RequireArgs(args []string, n int) error {
	if len(args) < n {
		return errors.New("not enough arguments")
	}
	return nil
}
