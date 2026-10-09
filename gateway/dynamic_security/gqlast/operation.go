package gqlast

import (
	"github.com/vektah/gqlparser/v2/ast"
)

// Operation 被选中的 operation（NG-T-G01：多 operation 文档只执行被选定者）。
type Operation struct {
	Definition *ast.OperationDefinition
	Name       string // 规范化操作名（匿名 operation 为 ""）
	Kind       string // query / mutation / subscription
}

// SelectOperation 按协议规则选择执行目标：
//   - 单 operation 文档：直接选定（operationName 缺省合法）；
//   - 多 operation + operationName 指定且存在 → 选定该 operation；
//   - 多 operation 未指定 operationName → ErrMultipleOps；
//   - 指定 operationName 不存在 → ErrOpNotFound；
//   - 文档无 operation → ErrNoOperation（防御性，ParseBounded 已先拦）。
func SelectOperation(doc *Document, operationName string) (*Operation, error) {
	ops := doc.AST.Operations
	if len(ops) == 0 {
		return nil, &Error{ErrNoOperation, "文档不包含 operation"}
	}
	if len(ops) == 1 {
		op := ops[0]
		return &Operation{Definition: op, Name: op.Name, Kind: string(op.Operation)}, nil
	}
	if operationName == "" {
		return nil, &Error{ErrMultipleOps,
			"文档包含多个 operation 但未指定 operationName（协议要求必须明确选择）"}
	}
	for _, op := range ops {
		if op.Name == operationName {
			return &Operation{Definition: op, Name: op.Name, Kind: string(op.Operation)}, nil
		}
	}
	return nil, &Error{ErrOpNotFound, "指定的 operationName 不存在: " + operationName}
}
