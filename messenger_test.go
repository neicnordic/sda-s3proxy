package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMessageFormatting(t *testing.T) {
	// Set up basic request for multipart upload
	r, _ := http.NewRequest("POST", "/user/new_file.txt", nil)
	r.Host = "localhost"
	r.Header.Set("content-length", "1234")
	r.Header.Set("x-amz-content-sha256", "checksum")

	msg, err := CreateMessageFromRequest(r)
	assert.Nil(t, err)
	assert.IsType(t, Event{}, msg)

	assert.Equal(t, "multipart-upload", msg.Operation)
	assert.Equal(t, int64(1234), msg.Filesize)
	assert.Equal(t, "/user/new_file.txt", msg.Filepath)
	assert.Equal(t, "user", msg.Username)
	assert.Equal(t, "sha256", msg.Checksum.Type)
	assert.Equal(t, "checksum", msg.Checksum.Value)

	// Test single shot upload
	r.Method = "PUT"
	msg, err = CreateMessageFromRequest(r)
	assert.Nil(t, err)
	assert.IsType(t, Event{}, msg)
	assert.Equal(t, "upload", msg.Operation)

	// Test GET upload
	r.Method = "GET"
	msg, err = CreateMessageFromRequest(r)
	assert.NotNil(t, err)
	assert.IsType(t, Event{}, msg)
	assert.Equal(t, "", msg.Operation)
}

func TestBuildMqURI(t *testing.T) {
	amqps := buildMqURI("localhost", "5555", "mquser", "mqpass", "/vhost", true)
	assert.Equal(t, "amqps://mquser:mqpass@localhost:5555/vhost", amqps)
	amqp := buildMqURI("localhost", "5555", "mquser", "mqpass", "/vhost", false)
	assert.Equal(t, "amqp://mquser:mqpass@localhost:5555/vhost", amqp)
}
