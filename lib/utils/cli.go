/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package utils

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unicode"

	"github.com/alecthomas/kingpin/v2"
	"github.com/gravitational/trace"
	"golang.org/x/term"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	logutils "github.com/gravitational/teleport/lib/utils/log"
)

// LoggingPurpose specifies which kind of application logging is
// to be configured for.
type LoggingPurpose int

const (
	// LoggingForDaemon configures logging for non-user interactive applications (teleport, tbot, tsh deamon).
	LoggingForDaemon LoggingPurpose = iota
	// LoggingForCLI configures logging for user face utilities (tctl, tsh).
	LoggingForCLI
	// LoggingForMCP configures logging for MCP servers.
	LoggingForMCP
)

// LoggingFormat defines the possible logging output formats.
type LoggingFormat = string

const (
	// LogFormatJSON configures logs to be emitted in json.
	LogFormatJSON LoggingFormat = "json"
	// LogFormatText configures logs to be emitted in a human readable text format.
	LogFormatText LoggingFormat = "text"
)

type logOpts struct {
	format LoggingFormat
	// osLogSubsystem is the subsystem used for all loggers created by this process
	// when sending logs to os_log on macOS. If empty, os_log won't be used.
	osLogSubsystem string
}

// LoggerOption enables customizing the global logger.
type LoggerOption func(opts *logOpts)

// WithLogFormat initializes the default logger with the provided format.
func WithLogFormat(format LoggingFormat) LoggerOption {
	return func(opts *logOpts) {
		opts.format = format
	}
}

func WithOSLog(subsystem string) LoggerOption {
	return func(opts *logOpts) {
		opts.osLogSubsystem = subsystem
	}
}

// IsTerminal checks whether writer is a terminal
func IsTerminal(w io.Writer) bool {
	switch v := w.(type) {
	case *os.File:
		return term.IsTerminal(int(v.Fd()))
	default:
		return false
	}
}

// InitLogger configures the global logger for a given purpose / verbosity level
func InitLogger(purpose LoggingPurpose, level slog.Level, opts ...LoggerOption) (*slog.Logger, error) {
	var o logOpts

	for _, opt := range opts {
		opt(&o)
	}

	// If debug or trace logging is not enabled for CLIs,
	// then discard all log output.
	if purpose == LoggingForCLI && level > slog.LevelDebug {
		logger := slog.New(slog.DiscardHandler)
		slog.SetDefault(logger)
		return logger, nil
	}

	var output string
	switch {
	case o.osLogSubsystem != "":
		output = logutils.LogOutputOSLog
	case purpose == LoggingForMCP:
		output = logutils.LogOutputMCP
		o.format = LogFormatJSON
	}

	logger, _, err := logutils.Initialize(logutils.Config{
		Severity:       level.String(),
		Format:         o.format,
		EnableColors:   IsTerminal(os.Stderr),
		Output:         output,
		OSLogSubsystem: o.osLogSubsystem,
	})
	return logger, trace.Wrap(err)
}

// FatalError is for CLI front-ends: it detects gravitational/trace debugging
// information, sends it to the logger, strips it off and prints a clean message to stderr
func FatalError(err error) {
	fmt.Fprintln(os.Stderr, UserMessageFromError(err))
	os.Exit(1)
}

// GetIterations provides a simple way to add iterations to the test
// by setting environment variable "ITERATIONS", by default it returns 1
func GetIterations() int {
	out := os.Getenv(teleport.IterationsEnvVar)
	if out == "" {
		return 1
	}
	iter, err := strconv.Atoi(out)
	if err != nil {
		panic(err)
	}
	slog.DebugContext(context.Background(), "Running tests multiple times due to presence of ITERATIONS environment variable", "iterations", iter)
	return iter
}

// UserMessageFromError returns user-friendly error message from error.
// The error message will be formatted for output depending on the debug
// flag
func UserMessageFromError(err error) string {
	if err == nil {
		return ""
	}
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		return trace.DebugReport(err)
	}
	var buf bytes.Buffer
	if runtime.GOOS == constants.WindowsOS {
		// TODO(timothyb89): Due to complications with globally enabling +
		// properly resetting Windows terminal ANSI processing, for now we just
		// disable color output. Otherwise, raw ANSI escapes will be visible to
		// users.
		fmt.Fprint(&buf, "ERROR: ")
	} else {
		fmt.Fprint(&buf, Color(Red, "ERROR: "))
	}
	formatErrorWriter(err, &buf)
	return buf.String()
}

// FormatErrorWithNewline returns user friendly error message from error.
// The error message is escaped if necessary. A newline is added if the error text
// does not end with a newline.
func FormatErrorWithNewline(err error) string {
	var buf bytes.Buffer
	formatErrorWriter(err, &buf)
	message := buf.String()
	if !strings.HasSuffix(message, "\n") {
		message = message + "\n"
	}
	return message
}

// formatErrorWriter formats the specified error into the provided writer.
// The error message is escaped if necessary
func formatErrorWriter(err error, w io.Writer) {
	if err == nil {
		return
	}
	if certErr := formatCertError(err); certErr != "" {
		fmt.Fprintln(w, certErr)
		return
	}

	msg := trace.UserMessage(err)
	// Error can be of type trace.proxyError where error message didn't get captured.
	if msg == "" {
		fmt.Fprintln(w, "please check Teleport's log for more details")
		return
	}

	fmt.Fprintln(w, AllowWhitespace(msg))
}

func formatCertError(err error) string {
	const unknownAuthority = `WARNING:

  The proxy you are connecting to has presented a certificate signed by a
  unknown authority. This is most likely due to either being presented
  with a self-signed certificate or the certificate was truly signed by an
  authority not known to the client.

  If you know the certificate is self-signed and would like to ignore this
  error use the --insecure flag.

  If you have your own certificate authority that you would like to use to
  validate the certificate chain presented by the proxy, set the
  SSL_CERT_FILE and SSL_CERT_DIR environment variables respectively and try
  again.

  If you think something malicious may be occurring, contact your Teleport
  system administrator to resolve this issue.
`
	if errors.As(err, &x509.UnknownAuthorityError{}) {
		return unknownAuthority
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return fmt.Sprintf("Cannot establish https connection to %s:\n%s\n%s\n",
			hostnameErr.Host,
			hostnameErr.Error(),
			"try a different hostname for --proxy or specify --insecure flag if you know what you're doing.")
	}

	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return fmt.Sprintf(`WARNING:

  The certificate presented by the proxy is invalid: %v.

  Contact your Teleport system administrator to resolve this issue.`, certInvalidErr)
	}

	// Check for less explicit errors. These are often emitted on Darwin
	if strings.Contains(err.Error(), "certificate is not trusted") {
		return unknownAuthority
	}

	return ""
}

const (
	// Bold is an escape code to format as bold or increased intensity
	Bold = 1
	// Red is an escape code for red terminal color
	Red = 31
	// Yellow is an escape code for yellow terminal color
	Yellow = 33
	// Blue is an escape code for blue terminal color
	Blue = 36
	// Gray is an escape code for gray terminal color
	Gray = 37
)

// Color formats the string in a terminal escape color
func Color(color int, v any) string {
	return fmt.Sprintf("\x1b[%dm%v\x1b[0m", color, v)
}

// InitCLIParser configures kingpin command line args parser with
// some defaults common for all Teleport CLI tools
func InitCLIParser(appName, appHelp string) (app *kingpin.Application) {
	app = kingpin.New(appName, appHelp)

	// make all flags repeatable, this makes the CLI easier to use.
	app.AllRepeatable(true)

	// hide "--help" flag
	app.HelpFlag.Hidden()
	app.HelpFlag.NoEnvar()

	// set our own help template
	return app.UsageTemplate(createUsageTemplate())
}

// InitHiddenCLIParser initializes a `kingpin.Application` that does not terminate the application
// or write any usage information to os.Stdout. Can be used in scenarios where multiple `kingpin.Application`
// instances are needed without interfering with subsequent parsing. Usage output is completely suppressed,
// and the default global `--help` flag is ignored to prevent the application from exiting.
func InitHiddenCLIParser() (app *kingpin.Application) {
	app = kingpin.New("", "")
	app.UsageWriter(io.Discard)
	app.Terminate(func(i int) {})

	return app
}

// createUsageTemplate creates an usage template for kingpin applications.
func createUsageTemplate(opts ...func(*usageTemplateOptions)) string {
	opt := &usageTemplateOptions{
		commandPrintfWidth: defaultCommandPrintfWidth,
	}

	for _, optFunc := range opts {
		optFunc(opt)
	}
	return fmt.Sprintf(defaultUsageTemplate, opt.commandPrintfWidth)
}

// SplitIdentifiers splits list of identifiers by commas/spaces/newlines.  Helpful when
// accepting lists of identifiers in CLI (role names, request IDs, etc).
func SplitIdentifiers(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
}

// EscapeControl escapes all ANSI escape sequences from string and returns a
// string that is safe to print on the CLI. This is to ensure that malicious
// servers can not hide output. For more details, see:
//   - https://sintonen.fi/advisories/scp-client-multiple-vulnerabilities.txt
func EscapeControl(s string) string {
	if needsQuoting(s) {
		return fmt.Sprintf("%q", s)
	}
	return s
}

// isAllowedWhitespace is a helper function for cli output escaping that returns
// true if a given rune is a whitespace character and allowed to be unescaped.
func isAllowedWhitespace(r rune) bool {
	switch r {
	case '\n', '\t', '\v':
		// newlines, tabs, vertical tabs are allowed whitespace.
		return true
	}
	return false
}

// AllowWhitespace escapes all ANSI escape sequences except some whitespace
// characters (\n \t \v) from string and returns a string that is safe to
// print on the CLI. This is to ensure that malicious servers can not hide
// output. For more details, see:
//   - https://sintonen.fi/advisories/scp-client-multiple-vulnerabilities.txt
func AllowWhitespace(s string) string {
	// loop over string searching for part to escape followed by allowed char.
	// example: `\tabc\ndef\t\n`
	// 1. part: ""    sep: "\t"
	// 2. part: "abc" sep: "\n"
	// 3. part: "def" sep: "\t"
	// 4. part: ""    sep: "\n"
	var sb strings.Builder
	// note that increment also happens at bottom of loop because we can
	// safely jump to place where allowedWhitespace was found.
	for i := 0; i < len(s); i++ {
		sepIdx := strings.IndexFunc(s[i:], isAllowedWhitespace)
		if sepIdx == -1 {
			// infalliable call, ignore error.
			_, _ = sb.WriteString(EscapeControl(s[i:]))
			// no separators remain.
			break
		}
		part := EscapeControl(s[i : i+sepIdx])
		_, _ = sb.WriteString(part)
		sep := s[i+sepIdx]
		_ = sb.WriteByte(sep)
		i += sepIdx
	}
	return sb.String()
}

// needsQuoting returns true if any non-printable characters are found.
func needsQuoting(text string) bool {
	for _, r := range text {
		if !strconv.IsPrint(r) {
			return true
		}
	}
	return false
}

// usageTemplateOptions defines options to format the usage template.
type usageTemplateOptions struct {
	// commandPrintfWidth is the width of the command name with padding, for
	//   {{.FullCommand | printf "%%-%ds"}}
	commandPrintfWidth int
}

// defaultCommandPrintfWidth is the default command printf width.
const defaultCommandPrintfWidth = 12

// defaultUsageTemplate is a fmt format that defines the usage template with
// compactly formatted commands. Should be only used in createUsageTemplate.
const defaultUsageTemplate = `{{define "FormatCommand" -}}
{{if .FlagSummary}} {{.FlagSummary}}{{end -}}
{{range .Args}} {{if not .Required}}[{{end}}<{{.Name}}>{{if .Value|IsCumulative}}...{{end}}{{if not .Required}}]{{end}}{{end -}}
{{end -}}

{{define "FormatCommands" -}}
{{range .FlattenedCommands -}}
{{if not .Hidden -}}
{{"  "}}{{.FullCommand | printf "%%-%ds"}}{{if .Default}} (Default){{end}} {{ .Help }}
{{end -}}
{{end -}}
{{end -}}

{{define "FormatUsage" -}}
{{template "FormatCommand" .}}{{if .Commands}} <command> [<args> ...]{{end}}
{{if .Help}}
{{.Help|Wrap 0 -}}
{{end -}}

{{end -}}

{{if .Context.SelectedCommand -}}
usage: {{.App.Name}} {{.Context.SelectedCommand}}{{template "FormatUsage" .Context.SelectedCommand}}
{{else -}}
Usage: {{.App.Name}}{{template "FormatUsage" .App}}
{{end -}}
{{if .Context.Flags -}}
Flags:
{{.Context.Flags|FlagsToTwoColumnsCompact|FormatTwoColumns}}
{{end -}}
{{if .Context.Args -}}
Args:
{{.Context.Args|ArgsToTwoColumns|FormatTwoColumns}}
{{end -}}
{{if .Context.SelectedCommand -}}

{{ if .Context.SelectedCommand.Commands -}}
Commands:
{{if .Context.SelectedCommand.Commands -}}
{{template "FormatCommands" .Context.SelectedCommand}}
{{end -}}
{{end -}}

{{else if .App.Commands -}}
Commands:
{{template "FormatCommands" .App}}
Try '{{.App.Name}} help [command]' to get help for a given command.
{{end -}}

{{ if .Context.SelectedCommand  -}}
Aliases:
{{ range .Context.SelectedCommand.Aliases -}}
{{ . }}
{{end -}}
{{end}}
`

// IsPredicateError determines if the error is from failing to parse predicate expression
// by checking if the error as a string contains predicate keywords.
func IsPredicateError(err error) bool {
	return strings.Contains(err.Error(), "predicate expression")
}

type PredicateError struct {
	Err error
}

func (p PredicateError) Error() string {
	return fmt.Sprintf("%s\nCheck syntax at https://goteleport.com/docs/reference/predicate-language/#resource-filtering", p.Err.Error())
}

// FormatAlert formats and colors the alert message if possible.
func FormatAlert(alert types.ClusterAlert) string {
	// TODO(timothyb89): Due to complications with globally enabling +
	// properly resetting Windows terminal ANSI processing, for now we just
	// disable color output. Otherwise, raw ANSI escapes will be visible to
	// users.
	var buf bytes.Buffer
	switch runtime.GOOS {
	case constants.WindowsOS:
		fmt.Fprint(&buf, alert.Spec.Message)
	default:
		switch alert.Spec.Severity {
		case types.AlertSeverity_HIGH:
			fmt.Fprint(&buf, Color(Red, alert.Spec.Message))
		case types.AlertSeverity_MEDIUM:
			fmt.Fprint(&buf, Color(Yellow, alert.Spec.Message))
		default:
			fmt.Fprint(&buf, alert.Spec.Message)
		}
	}
	return buf.String()
}

// FilterArguments filters the input arguments, keeping only those defined in the provided `kingpin.ApplicationModel`.
// For example, if the model defines only one boolean flag `--insecure`, all other arguments in `args`
// will be excluded, and only the `--insecure` flag will remain.
func FilterArguments(args []string, model *kingpin.ApplicationModel) []string {
	var result []string
	for _, flag := range model.Flags {
		for i := range args {
			if strings.HasPrefix(args[i], fmt.Sprint("--", flag.Name, "=")) {
				result = append(result, args[i])
				break
			}
			if args[i] == fmt.Sprint("--", flag.Name) {
				if flag.IsBoolFlag() {
					result = append(result, args[i])
				} else if i+2 <= len(args) {
					result = append(result, args[i], args[i+1])
				}
				break
			}
		}
	}
	return result
}
