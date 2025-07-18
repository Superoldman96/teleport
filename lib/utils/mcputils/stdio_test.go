/*
 * Teleport
 * Copyright (C) 2025  Gravitational, Inc.
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

package mcputils

import (
	"context"
	"io"
	"log"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gravitational/trace"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/utils/mcptest"
)

// TestStdioHelpers tests MessageReader and StdioMessageWriter by
// implementing a passthrough reverse proxy.
//
// The flow looks something like this:
// request: MCP client --> client message reader --> server message writer --> MCP server
// response: MCP client <-- client message writer <-- server message reader <-- MCP server
func TestStdioHelpers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Set up some counters for verification.
	var readClientNotifications int32
	var readClientRequests int32
	var readServerNotifications int32
	var readServerResponses int32

	// Pipes for hooking things up.
	clientStdin, writeToClient := io.Pipe()
	readFromClient, clientStdout := io.Pipe()
	serverStdin, writeToServer := io.Pipe()
	readFromServer, serverStdout := io.Pipe()
	t.Cleanup(func() {
		assert.NoError(t, trace.NewAggregate(
			clientStdin.Close(), writeToClient.Close(),
			readFromClient.Close(), clientStdout.Close(),
			serverStdin.Close(), writeToServer.Close(),
			readFromServer.Close(), serverStdout.Close(),
		))
	})

	// Make "low-level" message readers and writers for MITM proxy.
	clientMessageWriter := NewStdioMessageWriter(writeToClient)
	serverMessageWriter := NewStdioMessageWriter(writeToServer)

	clientMessageReader, err := NewMessageReader(MessageReaderConfig{
		ParentContext: context.Background(),
		Transport:     NewStdioReader(readFromClient),
		OnNotification: func(ctx context.Context, notification *JSONRPCNotification) error {
			atomic.AddInt32(&readClientNotifications, 1)
			return trace.Wrap(serverMessageWriter.WriteMessage(ctx, notification))
		},
		OnRequest: func(ctx context.Context, request *JSONRPCRequest) error {
			atomic.AddInt32(&readClientRequests, 1)
			return trace.Wrap(serverMessageWriter.WriteMessage(ctx, request))
		},
		OnParseError: ReplyParseError(clientMessageWriter),
	})
	require.NoError(t, err)
	clientMessageReaderClosed := make(chan struct{})
	go func() {
		clientMessageReader.Run(ctx)
		close(clientMessageReaderClosed)
	}()

	serverMessageReader, err := NewMessageReader(MessageReaderConfig{
		ParentContext: context.Background(),
		Transport:     NewStdioReader(readFromServer),
		OnNotification: func(ctx context.Context, notification *JSONRPCNotification) error {
			atomic.AddInt32(&readServerNotifications, 1)
			return trace.Wrap(clientMessageWriter.WriteMessage(ctx, notification))
		},
		OnResponse: func(ctx context.Context, response *JSONRPCResponse) error {
			atomic.AddInt32(&readServerResponses, 1)
			return trace.Wrap(clientMessageWriter.WriteMessage(ctx, response))
		},
		OnParseError: LogAndIgnoreParseError(slog.Default()),
	})
	require.NoError(t, err)
	serverMessageReaderClosed := make(chan struct{})
	serverMessageReaderCtx, serverMessageReaderCtxCancel := context.WithCancel(ctx)
	go func() {
		serverMessageReader.Run(serverMessageReaderCtx)
		close(serverMessageReaderClosed)
	}()

	// Make "high-level" MCP client and server with stdio transport as the two
	// ends.
	stdioClient := mcptest.NewStdioClient(t, clientStdin, clientStdout)

	stdioServer := mcpserver.NewStdioServer(mcptest.NewServer())
	stdioServer.SetErrorLogger(log.New(io.Discard, "", log.LstdFlags))
	go stdioServer.Listen(ctx, serverStdin, serverStdout)

	// Test things out.
	t.Run("client initialize", func(t *testing.T) {
		_, err := mcptest.InitializeClient(ctx, stdioClient)
		require.NoError(t, err)
	})

	t.Run("client call tool", func(t *testing.T) {
		mcptest.MustCallServerTool(t, ctx, stdioClient)
	})

	t.Run("reader closed by closing stdin", func(t *testing.T) {
		readFromClient.Close()
		select {
		case <-clientMessageReaderClosed:
		case <-time.After(time.Second * 2):
			require.Fail(t, "timeout waiting for reader closed by closing stdin")
		}
	})

	t.Run("reader closed by canceling context", func(t *testing.T) {
		serverMessageReaderCtxCancel()
		select {
		case <-serverMessageReaderClosed:
		case <-time.After(time.Second * 2):
			require.Fail(t, "timeout waiting for reader closed by canceling context")
		}
	})

	t.Run("verify counters", func(t *testing.T) {
		// client -> server: initialize request
		// server -> client: initialize response
		// client -> server: notifications/initialized
		// client -> server: tools\call request
		// server -> client: tools\call response
		assert.Equal(t, int32(1), atomic.LoadInt32(&readClientNotifications))
		assert.Equal(t, int32(2), atomic.LoadInt32(&readClientRequests))
		assert.Equal(t, int32(0), atomic.LoadInt32(&readServerNotifications))
		assert.Equal(t, int32(2), atomic.LoadInt32(&readServerResponses))
	})
}
