package telegram

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"gargoyle/internal/config"
)

type Bot struct {
	mu        sync.Mutex
	cfg       config.TelegramConfig
	offset    int
	stop      chan struct{}
	stopped   chan struct{}
	pairCode  string
	pairUntil time.Time
	saveUser  func(id int64) error
	execFn    func(cmd string) (string, error)
	statsFn   func() string
	wipeFn    func() error
	logf      func(format string, args ...any)
}

type Options struct {
	Config   config.TelegramConfig
	SaveUser func(id int64) error
	ExecFn   func(cmd string) (string, error)
	StatsFn  func() string
	WipeFn   func() error
	Logf     func(format string, args ...any)
}

func Start(opts Options) (*Bot, error) {
	if opts.Config.BotToken == "" {
		return nil, errors.New("telegram bot_token is empty")
	}
	b := &Bot{
		cfg:      opts.Config,
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
		saveUser: opts.SaveUser,
		execFn:   opts.ExecFn,
		statsFn:  opts.StatsFn,
		wipeFn:   opts.WipeFn,
		logf:     opts.Logf,
	}
	if b.logf == nil {
		b.logf = func(string, ...any) {}
	}
	if b.cfg.AllowedUserID == 0 && b.cfg.PairingTTL > 0 {
		b.pairCode = fmt.Sprintf("%06d", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(1000000))
		b.pairUntil = time.Now().Add(time.Duration(b.cfg.PairingTTL) * time.Second)
		b.logf("telegram: pairing code %s (valid %ds)", b.pairCode, b.cfg.PairingTTL)
	}
	go b.loop()
	return b, nil
}

func (b *Bot) Stop() {
	close(b.stop)
	<-b.stopped
}

func (b *Bot) loop() {
	defer close(b.stopped)
	for {
		select {
		case <-b.stop:
			return
		default:
		}
		if err := b.pollOnce(); err != nil {
			b.logf("telegram: %v", err)
			time.Sleep(3 * time.Second)
		}
	}
}

func (b *Bot) pollOnce() error {
	values := url.Values{}
	values.Set("timeout", "25")
	if b.offset > 0 {
		values.Set("offset", strconv.Itoa(b.offset))
	}
	resp, err := http.PostForm(b.apiURL("getUpdates"), values)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var result struct {
		OK     bool      `json:"ok"`
		Result []Update  `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if !result.OK {
		return errors.New("telegram api error")
	}
	for _, upd := range result.Result {
		if upd.UpdateID >= b.offset {
			b.offset = upd.UpdateID + 1
		}
		if upd.Message == nil {
			continue
		}
		b.handleMessage(upd.Message)
	}
	return nil
}

func (b *Bot) handleMessage(msg *Message) {
	if msg.From == nil || msg.Chat == nil {
		return
	}
	userID := msg.From.ID
	text := strings.TrimSpace(msg.Text)

	if b.cfg.AllowedUserID == 0 && b.pairCode != "" {
		if time.Now().After(b.pairUntil) {
			b.sendText(msg.Chat.ID, "Pairing expired. Restart Gargoyle to get a new code.")
			return
		}
		if strings.HasPrefix(text, "/pair ") {
			code := strings.TrimSpace(strings.TrimPrefix(text, "/pair "))
			if code == b.pairCode {
				b.cfg.AllowedUserID = userID
				b.pairCode = ""
				if b.saveUser != nil {
					_ = b.saveUser(userID)
				}
				b.sendText(msg.Chat.ID, "Paired. Access granted.")
			} else {
				b.sendText(msg.Chat.ID, "Invalid pairing code.")
			}
			return
		}
		b.sendText(msg.Chat.ID, "Access denied. Use /pair <code>.")
		return
	}

	if b.cfg.AllowedUserID != 0 && userID != b.cfg.AllowedUserID {
		b.sendText(msg.Chat.ID, "Access denied.")
		return
	}

	switch {
	case strings.HasPrefix(text, "/stats"):
		if b.cfg.AllowStats && b.statsFn != nil {
			b.sendText(msg.Chat.ID, b.statsFn())
		} else {
			b.sendText(msg.Chat.ID, "Stats disabled.")
		}
	case strings.HasPrefix(text, "/cli"):
		if !b.cfg.AllowCLI || b.execFn == nil {
			b.sendText(msg.Chat.ID, "CLI disabled.")
			return
		}
		cmd := strings.TrimSpace(strings.TrimPrefix(text, "/cli"))
		if cmd == "" {
			b.sendText(msg.Chat.ID, "Usage: /cli <command>")
			return
		}
		out, err := b.execFn(cmd)
		if err != nil {
			b.sendText(msg.Chat.ID, "Error: "+err.Error())
			return
		}
		b.sendText(msg.Chat.ID, out)
	case strings.HasPrefix(text, "/wipe"):
		if !b.cfg.AllowWipe || b.wipeFn == nil {
			b.sendText(msg.Chat.ID, "Wipe disabled.")
			return
		}
		if err := b.wipeFn(); err != nil {
			b.sendText(msg.Chat.ID, "Wipe error: "+err.Error())
			return
		}
		b.sendText(msg.Chat.ID, "Emergency wipe executed.")
	default:
		b.sendText(msg.Chat.ID, "Unknown command. Use /stats /cli /wipe")
	}
}

func (b *Bot) apiURL(method string) string {
	return "https://api.telegram.org/bot" + b.cfg.BotToken + "/" + method
}

func (b *Bot) sendText(chatID int64, text string) {
	if text == "" {
		text = "(empty)"
	}
	payload := url.Values{}
	payload.Set("chat_id", strconv.FormatInt(chatID, 10))
	payload.Set("text", truncate(text, 3500))
	req, err := http.NewRequest("POST", b.apiURL("sendMessage"), bytes.NewBufferString(payload.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 10 * time.Second}
	_, _ = client.Do(req)
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "..."
}

type Update struct {
	UpdateID int      `json:"update_id"`
	Message  *Message `json:"message"`
}

type Message struct {
	MessageID int   `json:"message_id"`
	From      *User `json:"from"`
	Chat      *Chat `json:"chat"`
	Text      string `json:"text"`
}

type User struct {
	ID int64 `json:"id"`
}

type Chat struct {
	ID int64 `json:"id"`
}
