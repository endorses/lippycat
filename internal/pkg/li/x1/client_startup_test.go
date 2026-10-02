//go:build li

package x1

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type startupTransportFunc func(*http.Request) (*http.Response, error)

func (f startupTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func startupResponse(status int) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}
}

func TestClient_ReportStartupRecoversAfterTimeout(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ADMFEndpoint:   "http://admf.example.test",
		RequestTimeout: 10 * time.Millisecond,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     2 * time.Millisecond,
		MaxRetries:     2,
	})
	require.NoError(t, err)
	defer client.Stop()

	type startupRequest struct {
		Message struct {
			TransactionID string `xml:"x1TransactionId"`
			IssueType     string `xml:"typeOfNeIssueMessage"`
			Description   string `xml:"description"`
		} `xml:"x1RequestMessage"`
	}
	var attempts []startupRequest
	client.httpClient.Transport = startupTransportFunc(func(r *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		attempts = append(attempts, startupRequest{})
		require.NoError(t, xml.Unmarshal(body, &attempts[len(attempts)-1]))
		if len(attempts) == 1 {
			// The ADMF may receive the notification but lose its response.
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(reportAcknowledgment(t, body, "")))), Header: make(http.Header)}, nil
	})

	require.NoError(t, client.ReportStartup(context.Background()))
	require.Len(t, attempts, 2)
	for _, attempt := range attempts {
		_, err := uuid.Parse(attempt.Message.TransactionID)
		require.NoError(t, err)
		require.Equal(t, NEIssueTypeStartup, attempt.Message.IssueType)
		require.Equal(t, "Network element started", attempt.Message.Description)
	}
	require.NotEqual(t, attempts[0].Message.TransactionID, attempts[1].Message.TransactionID,
		"a timeout resend is a new transaction under ETSI TS 103 221-1 clause 5.2.3")
	require.Equal(t, uint64(1), client.Stats().NEReportsSent)
	require.Zero(t, client.Stats().NEReportsFailed)
}

func TestClient_ReportStartupCancellation(t *testing.T) {
	for _, blockedRequest := range []bool{true, false} {
		name := "backoff"
		if blockedRequest {
			name = "request"
		}
		t.Run(name, func(t *testing.T) {
			client, err := NewClient(ClientConfig{
				ADMFEndpoint:   "http://admf.example.test",
				RequestTimeout: time.Hour,
				InitialBackoff: time.Hour,
				MaxBackoff:     time.Hour,
				MaxRetries:     2,
			})
			require.NoError(t, err)
			defer client.Stop()
			started := make(chan struct{})
			var once sync.Once
			client.httpClient.Transport = startupTransportFunc(func(r *http.Request) (*http.Response, error) {
				once.Do(func() { close(started) })
				if blockedRequest {
					<-r.Context().Done()
					return nil, r.Context().Err()
				}
				return startupResponse(http.StatusServiceUnavailable), nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			finished := make(chan error, 1)
			go func() { finished <- client.ReportStartup(ctx) }()
			<-started
			cancel()
			select {
			case err := <-finished:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(time.Second):
				t.Fatal("startup notification did not stop after cancellation")
			}
			require.Zero(t, client.Stats().NEReportsSent)
			require.Equal(t, uint64(1), client.Stats().NEReportsFailed)
		})
	}
}

func TestClient_ReportStartupRetriesAreBounded(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ADMFEndpoint:   "http://admf.example.test",
		InitialBackoff: time.Millisecond,
		MaxBackoff:     time.Millisecond,
		MaxRetries:     2,
	})
	require.NoError(t, err)
	defer client.Stop()
	attempts := 0
	client.httpClient.Transport = startupTransportFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		return startupResponse(http.StatusServiceUnavailable), nil
	})
	require.ErrorIs(t, client.ReportStartup(context.Background()), ErrRequestFailed)
	require.Equal(t, 3, attempts)
	require.Zero(t, client.Stats().NEReportsSent)
	require.Equal(t, uint64(1), client.Stats().NEReportsFailed)
}
