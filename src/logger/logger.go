package logger

import (
	"fmt"
	"path/filepath"
	"runtime"
	"time"
)

type VerboseLevel int

const (
	VerboseLevelInfo VerboseLevel = iota
	VerboseLevelWarning
	VerboseLevelError
	VerboseLevelFatal
)

var levelNames = []string{
	VerboseLevelInfo:    "INFO",
	VerboseLevelWarning: "WARNING",
	VerboseLevelError:   "ERROR",
	VerboseLevelFatal:   "FATAL",
}

var colorCodes = []string{
	VerboseLevelInfo:    "\033[36m",
	VerboseLevelWarning: "\033[33m",
	VerboseLevelError:   "\033[31m",
	VerboseLevelFatal:   "\033[31;1m",
}

const resetColor = "\033[0m"

func padRight(s string, pad string, length int) string {
	for len(s) < length {
		s = s + pad
	}
	return s
}
func padLevel(level VerboseLevel) string {
	return padRight(levelNames[level], " ", 7) // 7 is the length of the longest level name "WARNING"
}

type Logger struct {
	verboseLevel VerboseLevel
	parent       *Logger
	name         string

	printCaller   bool
	padCaller     int
	printTime     bool
	printLevel    bool
	padName       int
	timeFormat    string
	doColor       bool
	printNameTree bool
}

type Option func(*Logger)

func WithVerboseLevel(level VerboseLevel) Option {
	return func(l *Logger) {
		l.verboseLevel = level
	}
}

func WithPrintCaller(pad int) Option {
	return func(l *Logger) {
		l.printCaller = true
		l.padCaller = pad
	}
}

func WithPrintTime(format string) Option {
	return func(l *Logger) {
		l.printTime = true
		l.timeFormat = format
	}
}

func WithPrintLevel() Option {
	return func(l *Logger) {
		l.printLevel = true
	}
}

func WithPrintNameTree(pad int) Option {
	return func(l *Logger) {
		l.printNameTree = true
		l.padName = pad
	}
}

func WithColor() Option {
	return func(l *Logger) {
		l.doColor = true
	}
}

func NewLogger(name string, options ...Option) *Logger {
	l := &Logger{
		verboseLevel: VerboseLevelInfo,
		name:         name,

		printCaller:   false,
		padCaller:     0,
		printTime:     false,
		printLevel:    false,
		padName:       0,
		timeFormat:    time.RFC3339,
		doColor:       false,
		printNameTree: false,
	}
	for _, option := range options {
		option(l)
	}
	return l
}

func (l *Logger) AddChild(name string) *Logger {
	newl := &Logger{
		verboseLevel: l.verboseLevel,
		parent:       l,

		name: name,

		printCaller: l.printCaller,
		padCaller:   l.padCaller,
		printTime:   l.printTime,
		printLevel:  l.printLevel,
		padName:     l.padName,
	}
	return newl
}

func (l *Logger) getTreeName() string {
	if !l.printNameTree {
		return " [" + l.name + "] "
	}
	fullName := l.name
	ptr := l.parent
	for ptr != nil {
		fullName = ptr.name + "." + fullName
		ptr = ptr.parent
	}
	if l.padName > 0 {
		fullName = padRight(fullName, " ", l.padName)
	}
	return fullName
}

func (l *Logger) getDateTime() string {
	if !l.printTime {
		return ""
	}
	return time.Now().Format(l.timeFormat)
}

func (l *Logger) getCaller() string {
	if !l.printCaller {
		return ""
	}
	_, file, line, _ := runtime.Caller(3)
	file = filepath.Base(file)
	callerStr := fmt.Sprintf("%s:%d", file, line)
	if l.padCaller > 0 {
		callerStr = padRight(callerStr, " ", l.padCaller)
	}
	return callerStr
}

func (l *Logger) getLevel(level VerboseLevel) string {
	if !l.printLevel {
		return ""
	}
	return " | " + padLevel(level) + " | "
}

func (l *Logger) print(level VerboseLevel, doNewLine bool, args ...any) {
	if level < l.verboseLevel {
		return
	}
	name := l.getTreeName()
	timeStr := l.getDateTime()
	levelStr := l.getLevel(level)
	callerStr := l.getCaller()

	var postfix string

	if doNewLine {
		postfix = "\n"
	} else {
		postfix = ""
	}

	res := fmt.Sprintf("%s%s%s%s > %s%s", timeStr, levelStr, name, callerStr, fmt.Sprint(args...), postfix)

	if l.doColor {
		res = colorCodes[level] + res + resetColor
	}

	fmt.Print(res)
}

func (l *Logger) Info(args ...any) {
	l.print(VerboseLevelInfo, false, args...)
}

func (l *Logger) Infoln(args ...any) {
	l.print(VerboseLevelInfo, true, args...)
}

func (l *Logger) Infof(format string, args ...any) {
	l.print(VerboseLevelInfo, false, fmt.Sprintf(format, args...))
}

func (l *Logger) Warning(args ...any) {
	l.print(VerboseLevelWarning, false, args...)
}

func (l *Logger) Warningln(args ...any) {
	l.print(VerboseLevelWarning, true, args...)
}

func (l *Logger) Warningf(format string, args ...any) {
	l.print(VerboseLevelWarning, false, fmt.Sprintf(format, args...))
}

func (l *Logger) Error(args ...any) {
	l.print(VerboseLevelError, false, args...)
}

func (l *Logger) Errorln(args ...any) {
	l.print(VerboseLevelError, true, args...)
}

func (l *Logger) Errorf(format string, args ...any) {
	l.print(VerboseLevelError, false, fmt.Sprintf(format, args...))
}

func (l *Logger) Fatal(args ...any) {
	l.print(VerboseLevelFatal, false, args...)
	panic(fmt.Sprint(args...))
}

func (l *Logger) Fatalln(args ...any) {
	l.print(VerboseLevelFatal, true, args...)
	panic(fmt.Sprintln(args...))
}

func (l *Logger) Fatalf(format string, args ...any) {
	l.print(VerboseLevelFatal, false, fmt.Sprintf(format, args...))
	panic(fmt.Sprintf(format, args...))
}

func (l *Logger) V(level int) bool {
	return level <= int(l.verboseLevel)
}
