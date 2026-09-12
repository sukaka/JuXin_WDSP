package aiorchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Task AI 任务记录（一次编排执行）。
type Task struct {
	ID             uuid.UUID  `json:"id"`
	SessionID      uuid.UUID  `json:"session_id"`
	SessionTitle   string     `json:"session_title"`
	TaskType       string     `json:"task_type"`
	Status         string     `json:"status"`
	RiskLevel      string     `json:"risk_level"`
	PlanSummary    string     `json:"plan_summary"`
	StartedAt      *time.Time `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at"`
	FailureCode    string     `json:"failure_code"`
	FailureMessage string     `json:"failure_message"`
	CreatedAt      time.Time  `json:"created_at"`
}

// TaskStore 任务记录持久化。
type TaskStore struct {
	db *pgxpool.Pool
}

// NewTaskStore 创建任务存储。
func NewTaskStore(db *pgxpool.Pool) *TaskStore {
	return &TaskStore{db: db}
}

// Create 登记任务（RUNNING）。
func (s *TaskStore) Create(ctx context.Context, id, sessionID uuid.UUID, taskType, riskLevel, planSummary string) error {
	_, err := s.db.Exec(ctx, `
INSERT INTO ai_tasks (id, session_id, task_type, status, risk_level, plan_summary, started_at)
VALUES ($1, $2, $3, 'RUNNING', $4, $5, now())`, id, sessionID, taskType, riskLevel, planSummary)
	if err != nil {
		return fmt.Errorf("create ai task: %w", err)
	}
	return nil
}

// Finish 结束任务（SUCCESS/PARTIAL_SUCCESS/FAILED/CANCELLED）。
func (s *TaskStore) Finish(ctx context.Context, id uuid.UUID, status, failureCode, failureMessage string) error {
	if len(failureMessage) > 500 {
		failureMessage = failureMessage[:500]
	}
	_, err := s.db.Exec(ctx, `
UPDATE ai_tasks SET status = $2, finished_at = now(), failure_code = $3, failure_message = $4
WHERE id = $1`, id, status, failureCode, failureMessage)
	if err != nil {
		return fmt.Errorf("finish ai task: %w", err)
	}
	return nil
}

// List 按用户分页列出任务（经会话归属过滤）。
func (s *TaskStore) List(ctx context.Context, userID uuid.UUID, status, taskType string, page, pageSize int) ([]Task, int64, error) {
	where := "s.user_id = $1"
	args := []interface{}{userID}
	n := 2
	if status != "" {
		where += fmt.Sprintf(" AND t.status = $%d", n)
		args = append(args, status)
		n++
	}
	if taskType != "" {
		where += fmt.Sprintf(" AND t.task_type = $%d", n)
		args = append(args, taskType)
		n++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM ai_tasks t JOIN ai_sessions s ON s.id = t.session_id WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count ai tasks: %w", err)
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT t.id, t.session_id, s.title, t.task_type, t.status, t.risk_level, t.plan_summary,
       t.started_at, t.finished_at, t.failure_code, t.failure_message, t.created_at
FROM ai_tasks t JOIN ai_sessions s ON s.id = t.session_id
WHERE `+where+` ORDER BY t.created_at DESC LIMIT $`+fmt.Sprint(n)+` OFFSET $`+fmt.Sprint(n+1), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list ai tasks: %w", err)
	}
	defer rows.Close()
	out := []Task{}
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.SessionID, &t.SessionTitle, &t.TaskType, &t.Status, &t.RiskLevel,
			&t.PlanSummary, &t.StartedAt, &t.FinishedAt, &t.FailureCode, &t.FailureMessage, &t.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan ai task: %w", err)
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// Get 取单个任务（校验属主）。
func (s *TaskStore) Get(ctx context.Context, id, userID uuid.UUID) (*Task, error) {
	var t Task
	err := s.db.QueryRow(ctx, `
SELECT t.id, t.session_id, s.title, t.task_type, t.status, t.risk_level, t.plan_summary,
       t.started_at, t.finished_at, t.failure_code, t.failure_message, t.created_at
FROM ai_tasks t JOIN ai_sessions s ON s.id = t.session_id
WHERE t.id = $1 AND s.user_id = $2`, id, userID).
		Scan(&t.ID, &t.SessionID, &t.SessionTitle, &t.TaskType, &t.Status, &t.RiskLevel,
			&t.PlanSummary, &t.StartedAt, &t.FinishedAt, &t.FailureCode, &t.FailureMessage, &t.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get ai task: %w", err)
	}
	return &t, nil
}

// StartAgentRun 登记 Agent 运行（RUNNING）；agent_code 未注册时返回 false 跳过。
func (s *TaskStore) StartAgentRun(ctx context.Context, taskID uuid.UUID, agentCode, inputSummary string) (uuid.UUID, bool, error) {
	var agentID uuid.UUID
	err := s.db.QueryRow(ctx, `SELECT id FROM ai_agents WHERE code = $1`, agentCode).Scan(&agentID)
	if err != nil {
		return uuid.Nil, false, nil // 未注册的 code（如 dispatcher）不落库
	}
	var id uuid.UUID
	if r := []rune(inputSummary); len(r) > 500 {
		inputSummary = string(r[:500])
	}
	if err := s.db.QueryRow(ctx, `
INSERT INTO ai_agent_runs (task_id, agent_id, status, input_summary, started_at)
VALUES ($1, $2, 'RUNNING', $3, now()) RETURNING id`, taskID, agentID, inputSummary).Scan(&id); err != nil {
		return uuid.Nil, false, fmt.Errorf("insert ai agent run: %w", err)
	}
	return id, true, nil
}

// FinishAgentRun 结束 Agent 运行（SUCCESS/FAILED/CANCELLED）。
func (s *TaskStore) FinishAgentRun(ctx context.Context, runID uuid.UUID, status, outputSummary, errorCode string) error {
	r := []rune(outputSummary)
	if len(r) > 1000 {
		outputSummary = string(r[:1000])
	}
	if len(errorCode) > 50 {
		errorCode = errorCode[:50]
	}
	_, err := s.db.Exec(ctx, `
UPDATE ai_agent_runs SET status = $2, output_summary = $3, error_code = $4, finished_at = now()
WHERE id = $1`, runID, status, outputSummary, errorCode)
	if err != nil {
		return fmt.Errorf("finish ai agent run: %w", err)
	}
	return nil
}
