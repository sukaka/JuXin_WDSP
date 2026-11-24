//go:build !linux && !darwin && !windows

package service

import (
	"context"
	"errors"
)

type unsupportedManager struct{}

func NewManager() Manager { return &unsupportedManager{} }

func (m *unsupportedManager) ServiceName() string    { return LinuxServiceName }
func (m *unsupportedManager) UnitPath() string       { return "" }
func (m *unsupportedManager) CheckPrivileges() error { return errors.New("当前平台不支持系统服务管理") }
func (m *unsupportedManager) Install(Config) error   { return errors.New("当前平台不支持系统服务管理") }
func (m *unsupportedManager) Uninstall() error       { return errors.New("当前平台不支持系统服务管理") }
func (m *unsupportedManager) Start() error           { return errors.New("当前平台不支持系统服务管理") }
func (m *unsupportedManager) Stop() error            { return errors.New("当前平台不支持系统服务管理") }
func (m *unsupportedManager) Restart() error         { return errors.New("当前平台不支持系统服务管理") }
func (m *unsupportedManager) Status() (StatusInfo, error) {
	return StatusInfo{ServiceName: LinuxServiceName, State: StateUnknown, Detail: "unsupported"}, nil
}

func IsRunningAsService() bool                                     { return false }
func RunIfService(_ func(ctx context.Context) error) (bool, error) { return false, nil }
