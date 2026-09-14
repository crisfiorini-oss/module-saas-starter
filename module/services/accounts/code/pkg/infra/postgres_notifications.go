package infra

import (
	"context"
	"errors"
	"time"

	"accounts/pkg/business"
)

func (s *PostgresStore) CreateNotification(ctx context.Context, n *business.Notification) error {
	q := s.getQueryExecutor(ctx)
	result, err := q.Exec(ctx, `
		INSERT INTO notifications (id, user_id, org_id, title, body, type, action_url, resource_type, resource_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id
		WHERE notifications.user_id = EXCLUDED.user_id
		  AND notifications.org_id IS NOT DISTINCT FROM EXCLUDED.org_id
		  AND notifications.title = EXCLUDED.title
		  AND notifications.body = EXCLUDED.body
		  AND notifications.type = EXCLUDED.type
		  AND notifications.action_url IS NOT DISTINCT FROM EXCLUDED.action_url
		  AND notifications.resource_type IS NOT DISTINCT FROM EXCLUDED.resource_type
		  AND notifications.resource_id IS NOT DISTINCT FROM EXCLUDED.resource_id`,
		n.ID, n.UserID, nilIfEmpty(n.OrgID), n.Title, n.Body, n.Type, nilIfEmpty(n.ActionURL),
		nilIfEmpty(n.ResourceType), nilIfEmpty(n.ResourceID))
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return errors.New("notification idempotency key conflicts with an existing notification")
	}
	return nil
}

func (s *PostgresStore) ListNotifications(ctx context.Context, userID string, pageSize int, pageToken string) ([]*business.Notification, string, error) {
	q := s.getQueryExecutor(ctx)

	query := `
		SELECT id, user_id, org_id, title, body, type, action_url, resource_type, resource_id, read_at, created_at
		FROM notifications
		WHERE user_id = $1`
	args := []any{userID}

	if pageToken != "" {
		query += ` AND created_at < $2`
		args = append(args, pageToken)
		query += ` ORDER BY created_at DESC LIMIT $3`
		args = append(args, pageSize)
	} else {
		query += ` ORDER BY created_at DESC LIMIT $2`
		args = append(args, pageSize)
	}

	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var notifications []*business.Notification
	for rows.Next() {
		var n business.Notification
		var orgID, actionURL, resourceType, resourceID *string
		var readAt *time.Time

		err := rows.Scan(&n.ID, &n.UserID, &orgID, &n.Title, &n.Body, &n.Type,
			&actionURL, &resourceType, &resourceID, &readAt, &n.CreatedAt)
		if err != nil {
			return nil, "", err
		}
		if orgID != nil {
			n.OrgID = *orgID
		}
		if actionURL != nil {
			n.ActionURL = *actionURL
		}
		if resourceType != nil {
			n.ResourceType = *resourceType
		}
		if resourceID != nil {
			n.ResourceID = *resourceID
		}
		n.ReadAt = readAt
		notifications = append(notifications, &n)
	}

	// Next page token is the created_at of the last item
	var nextToken string
	if len(notifications) == pageSize {
		nextToken = notifications[len(notifications)-1].CreatedAt.Format(time.RFC3339Nano)
	}

	return notifications, nextToken, nil
}

func (s *PostgresStore) GetUnreadCount(ctx context.Context, userID string) (int, error) {
	q := s.getQueryExecutor(ctx)
	var count int
	err := q.QueryRow(ctx, `
		SELECT COUNT(*) FROM notifications
		WHERE user_id = $1 AND read_at IS NULL`, userID).Scan(&count)
	return count, err
}

func (s *PostgresStore) MarkNotificationRead(ctx context.Context, id string) error {
	q := s.getQueryExecutor(ctx)
	_, err := q.Exec(ctx, `
		UPDATE notifications SET read_at = NOW()
		WHERE id = $1 AND read_at IS NULL`, id)
	return err
}

func (s *PostgresStore) MarkAllNotificationsRead(ctx context.Context, userID string) error {
	q := s.getQueryExecutor(ctx)
	_, err := q.Exec(ctx, `
		UPDATE notifications SET read_at = NOW()
		WHERE user_id = $1 AND read_at IS NULL`, userID)
	return err
}

func (s *PostgresStore) DeleteNotification(ctx context.Context, id string) error {
	q := s.getQueryExecutor(ctx)
	_, err := q.Exec(ctx, `DELETE FROM notifications WHERE id = $1`, id)
	return err
}

// GetNotificationUserID resolves notification.id → user_id. Called
// under WithControlPlane by Service.MarkRead / DeleteNotification before
// entering the owner's WithUserTx for the actual mutation. Returns
// ("", nil) on miss; caller decides whether that's a 404 or an
// authz failure.
func (s *PostgresStore) GetNotificationUserID(ctx context.Context, id string) (string, error) {
	q := s.getQueryExecutor(ctx)
	var userID string
	err := q.QueryRow(ctx, `SELECT user_id FROM notifications WHERE id = $1`, id).Scan(&userID)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return "", nil
		}
		return "", err
	}
	return userID, nil
}
