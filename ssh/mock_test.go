/*
 * Copyright The Titan Project Contributors.
 */
package ssh

import (
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/ssh"
	"net"
)

type MockConn struct {
	mock.Mock
}

func (m *MockConn) User() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockConn) SessionID() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

func (m *MockConn) ClientVersion() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

func (m *MockConn) ServerVersion() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

func (m *MockConn) RemoteAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockConn) LocalAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	args := m.Called(name, wantReply, payload)
	return args.Bool(0), args.Get(1).([]byte), args.Error(2)
}

func (m MockConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	args := m.Called(name, data)
	return args.Get(0).(ssh.Channel), args.Get(1).(<-chan *ssh.Request), args.Error(2)
}

func (m MockConn) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m MockConn) Wait() error {
	args := m.Called()
	return args.Error(0)
}
