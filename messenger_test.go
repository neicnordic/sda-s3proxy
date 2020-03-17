package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildMqURI(t *testing.T) {
	amqps := buildMqURI("localhost", "5555", "mquser", "mqpass", "/vhost", true)
	assert.Equal(t, "amqps://mquser:mqpass@localhost:5555/vhost", amqps)
	amqp := buildMqURI("localhost", "5555", "mquser", "mqpass", "/vhost", false)
	assert.Equal(t, "amqp://mquser:mqpass@localhost:5555/vhost", amqp)
}
