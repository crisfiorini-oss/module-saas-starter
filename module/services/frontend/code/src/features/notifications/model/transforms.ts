import { timestampDate } from "@bufbuild/protobuf/wkt";
import type { Notification as NotificationMessage } from "@/gen/saas/accounts/v1/notifications_pb";
import type { Notification, NotificationType } from "./types";

const notificationActionBase = new URL("https://notification.invalid");

/**
 * Narrows a stored action URL to a same-origin path. Shape only — authority is
 * a separate question, settled server-side when the link is followed.
 */
export function notificationActionUrl(actionUrl: string): string | undefined {
	if (!actionUrl.startsWith("/")) {
		return undefined;
	}
	try {
		const resolved = new URL(actionUrl, notificationActionBase);
		if (resolved.origin !== notificationActionBase.origin) {
			return undefined;
		}
		return `${resolved.pathname}${resolved.search}${resolved.hash}`;
	} catch {
		return undefined;
	}
}

export function toNotification(message: NotificationMessage): Notification {
	return {
		id: message.id,
		title: message.title,
		body: message.body,
		type: message.type as NotificationType,
		read: message.readAt !== undefined,
		createdAt: message.createdAt
			? timestampDate(message.createdAt).toISOString()
			: new Date(0).toISOString(),
		actionUrl: notificationActionUrl(message.actionUrl),
	};
}

export function formatNotificationType(type: NotificationType): string {
	switch (type) {
		case "info":
			return "Info";
		case "success":
			return "Success";
		case "warning":
			return "Warning";
		case "error":
			return "Error";
		case "billing":
			return "Billing";
		case "security":
			return "Security";
		default:
			return "Notification";
	}
}

/** Lucide icon name for each notification type. */
export function getNotificationIcon(type: NotificationType): string {
	switch (type) {
		case "info":
			return "Info";
		case "success":
			return "CheckCircle";
		case "warning":
			return "AlertTriangle";
		case "error":
			return "XCircle";
		case "billing":
			return "CreditCard";
		case "security":
			return "Shield";
		default:
			return "Bell";
	}
}

export function timeAgo(dateString: string): string {
	const now = Date.now();
	const then = new Date(dateString).getTime();
	const diffMs = now - then;

	const seconds = Math.floor(diffMs / 1000);
	if (seconds < 60) return "just now";

	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m ago`;

	const hours = Math.floor(minutes / 60);
	if (hours < 24) return `${hours}h ago`;

	const days = Math.floor(hours / 24);
	if (days < 7) return `${days}d ago`;

	const weeks = Math.floor(days / 7);
	if (weeks < 4) return `${weeks}w ago`;

	return new Intl.DateTimeFormat("en-US", {
		month: "short",
		day: "numeric",
	}).format(new Date(dateString));
}
