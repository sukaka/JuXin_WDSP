// Package apigroups 提供业务功能分组与真实 API 接口成员管理。
package apigroups

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	PermRead   = "api_endpoint_group.read"
	PermManage = "api_endpoint_group.manage"

	maxCodeLength        = 64
	maxNameLength        = 128
	maxDescriptionLength = 512
	maxPageSize          = 100
)

var (
	ErrNotFound            = errors.New("api endpoint group not found")
	ErrApplicationNotFound = errors.New("application not found")
	ErrEndpointNotFound    = errors.New("api endpoint not found")
	ErrMemberNotFound      = errors.New("api endpoint group member not found")
	ErrDuplicate           = errors.New("api endpoint group code already exists")
	ErrDuplicateMember     = errors.New("api endpoint group member already exists")
	ErrApplicationMismatch = errors.New("api endpoint belongs to another application")
)

var codePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

type ValidationError struct{ message string }

func (e *ValidationError) Error() string { return e.message }

func invalidf(format string, args ...any) error {
	return &ValidationError{message: fmt.Sprintf(format, args...)}
}

type Group struct {
	ID              uuid.UUID `json:"id"`
	ApplicationID   uuid.UUID `json:"application_id"`
	ApplicationName string    `json:"application_name"`
	Code            string    `json:"code"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Enabled         bool      `json:"enabled"`
	EndpointCount   int64     `json:"endpoint_count"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type CreateInput struct {
	ApplicationID uuid.UUID
	Code          string
	Name          string
	Description   string
	Enabled       bool
}

type UpdateInput struct {
	Code        string
	Name        string
	Description string
	Enabled     bool
}

type ListFilter struct {
	ApplicationID *uuid.UUID
	Page          int
	PageSize      int
}

type Endpoint struct {
	ID             uuid.UUID  `json:"id"`
	ApplicationID  *uuid.UUID `json:"application_id"`
	HTTPMethod     string     `json:"http_method"`
	NormalizedPath string     `json:"normalized_path"`
	EndpointKey    string     `json:"endpoint_key"`
	AssetStatus    string     `json:"asset_status"`
	AddedAt        time.Time  `json:"added_at"`
}

type Member struct {
	GroupID    uuid.UUID `json:"group_id"`
	EndpointID uuid.UUID `json:"endpoint_id"`
	CreatedAt  time.Time `json:"created_at"`
}

func normalizeFields(code, name, description string) (string, string, string, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	if utf8.RuneCountInString(code) > maxCodeLength || !codePattern.MatchString(code) {
		return "", "", "", invalidf("code 须为 1-%d 个字符并匹配 ^[A-Z][A-Z0-9_]*$（自动转为大写）", maxCodeLength)
	}
	if name == "" || utf8.RuneCountInString(name) > maxNameLength {
		return "", "", "", invalidf("name 必填且不超过 %d 个字符", maxNameLength)
	}
	if utf8.RuneCountInString(description) > maxDescriptionLength {
		return "", "", "", invalidf("description 不超过 %d 个字符", maxDescriptionLength)
	}
	return code, name, description, nil
}

func validateCreate(in *CreateInput) error {
	if in.ApplicationID == uuid.Nil {
		return invalidf("application_id 必填")
	}
	code, name, description, err := normalizeFields(in.Code, in.Name, in.Description)
	if err != nil {
		return err
	}
	in.Code, in.Name, in.Description = code, name, description
	return nil
}

func validateUpdate(in *UpdateInput) error {
	code, name, description, err := normalizeFields(in.Code, in.Name, in.Description)
	if err != nil {
		return err
	}
	in.Code, in.Name, in.Description = code, name, description
	return nil
}

func normalizePage(page, pageSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > maxPageSize {
		pageSize = 20
	}
	return page, pageSize
}
