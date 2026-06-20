package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

var (
	mu  sync.Mutex
	out *log.Logger
)

func Init(path string) error {
	if path == "" {
		return nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	mu.Lock()
	defer mu.Unlock()
	out = log.New(f, "", log.LstdFlags|log.Lmicroseconds)
	out.Printf("--- logger started path=%s ---", path)
	return nil
}

func enabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return out != nil
}

func write(level, msg string) {
	mu.Lock()
	defer mu.Unlock()
	if out == nil {
		return
	}
	out.Printf("[%s] %s", level, msg)
}

func Info(msg string) {
	if enabled() {
		write("INFO", msg)
	}
}

func Warn(msg string) {
	if enabled() {
		write("WARN", msg)
	}
}

func Error(msg string) {
	if enabled() {
		write("ERROR", msg)
	}
}

func Infof(format string, args ...any) {
	Info(fmt.Sprintf(format, args...))
}

func Warnf(format string, args ...any) {
	Warn(fmt.Sprintf(format, args...))
}

func Errorf(format string, args ...any) {
	Error(fmt.Sprintf(format, args...))
}

func Writer() io.Writer {
	mu.Lock()
	defer mu.Unlock()
	if out == nil {
		return io.Discard
	}
	return out.Writer()
}
