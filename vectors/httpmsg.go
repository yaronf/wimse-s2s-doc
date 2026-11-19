package vectors

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type parsedHTTP struct {
	IsResponse bool
	Request    *http.Request
	Response   *http.Response
	Raw        string
}

func parseHTTPMessage(raw string) (*parsedHTTP, error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	trim := strings.TrimSpace(raw)
	if strings.HasPrefix(trim, "HTTP/") {
		return parseResponse(raw)
	}
	return parseRequest(raw)
}

func parseRequest(raw string) (*parsedHTTP, error) {
	// Ensure CRLF for http.ReadRequest; inject Content-Length when body present without it.
	msg := normalizeHTTP(raw)
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(msg)))
	if err != nil {
		return nil, fmt.Errorf("read request: %w", err)
	}
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	return &parsedHTTP{IsResponse: false, Request: req, Raw: raw}, nil
}

func parseResponse(raw string) (*parsedHTTP, error) {
	msg := normalizeHTTP(raw)
	res, err := http.ReadResponse(bufio.NewReader(strings.NewReader(msg)), nil)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if res.Body != nil {
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		res.Body = io.NopCloser(bytes.NewReader(body))
		res.ContentLength = int64(len(body))
	}
	return &parsedHTTP{IsResponse: true, Response: res, Raw: raw}, nil
}

func normalizeHTTP(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	parts := strings.SplitN(raw, "\n\n", 2)
	head := parts[0]
	body := ""
	if len(parts) == 2 {
		body = parts[1]
	}
	// Drop duplicate Content-Length we may add; ensure one if body non-empty.
	var lines []string
	hasCL := false
	for _, line := range strings.Split(head, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			hasCL = true
		}
		lines = append(lines, line)
	}
	if body != "" && !hasCL {
		lines = append(lines, "Content-Length: "+strconv.Itoa(len(body)))
	}
	out := strings.Join(lines, "\r\n") + "\r\n\r\n" + body
	return out
}

func dumpRequestMessage(req *http.Request) (string, error) {
	var buf bytes.Buffer
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", req.Method, path)
	if req.Host != "" && req.Header.Get("Host") == "" {
		fmt.Fprintf(&buf, "Host: %s\r\n", req.Host)
	}
	if err := req.Header.Write(&buf); err != nil {
		return "", err
	}
	buf.WriteString("\r\n")
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return "", err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		buf.Write(body)
	}
	return buf.String(), nil
}

func dumpResponseMessage(res *http.Response) (string, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "HTTP/1.1 %s\r\n", res.Status)
	if err := res.Header.Write(&buf); err != nil {
		return "", err
	}
	buf.WriteString("\r\n")
	if res.Body != nil {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return "", err
		}
		res.Body = io.NopCloser(bytes.NewReader(body))
		buf.Write(body)
	}
	return buf.String(), nil
}

func cloneRequest(req *http.Request) *http.Request {
	c := req.Clone(req.Context())
	c.Header = req.Header.Clone()
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		c.Body = io.NopCloser(bytes.NewReader(body))
		c.ContentLength = int64(len(body))
		c.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	return c
}
