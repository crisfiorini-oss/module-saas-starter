"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCheck, X } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { Button, Separator, Skeleton } from "@/shared/ui";
import { timeAgo } from "../model/transforms";
import { notificationMutations } from "../service/mutations";
import { notificationQueries } from "../service/queries";

interface NotificationPanelProps {
	onClose: () => void;
}

export function NotificationPanel({ onClose }: NotificationPanelProps) {
	const queryClient = useQueryClient();
	const router = useRouter();
	const { data, isLoading } = useQuery(notificationQueries.list(10));
	const notifications = data?.notifications ?? [];

	const markReadMutation = useMutation({
		mutationFn: (id: string) => notificationMutations.markRead(id),
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["notifications"] });
		},
	});

	const resolveActionMutation = useMutation({
		mutationFn: (id: string) => notificationMutations.resolveAction(id),
		onSuccess: (actionUrl) => {
			if (!actionUrl) {
				return;
			}
			onClose();
			router.push(actionUrl);
		},
		onError: () => toast.error("This notification is no longer available"),
	});

	const markAllReadMutation = useMutation({
		mutationFn: () => notificationMutations.markAllRead(),
		onSuccess: () => {
			toast.success("All notifications marked as read");
			queryClient.invalidateQueries({ queryKey: ["notifications"] });
		},
		onError: () => toast.error("Failed to mark all as read"),
	});

	return (
		<div className="absolute right-0 top-full z-50 mt-2 w-80 rounded-lg border bg-popover shadow-lg">
			<div className="flex items-center justify-between border-b px-4 py-3">
				<h3 className="text-sm font-semibold">Notifications</h3>
				<div className="flex items-center gap-1">
					<Button
						variant="ghost"
						size="sm"
						className="h-7 px-2 text-xs"
						onClick={() => markAllReadMutation.mutate()}
						disabled={markAllReadMutation.isPending}
					>
						<CheckCheck className="mr-1 h-3 w-3" />
						Mark all read
					</Button>
					<Button
						variant="ghost"
						size="sm"
						className="h-7 w-7 p-0"
						onClick={onClose}
					>
						<X className="h-3 w-3" />
					</Button>
				</div>
			</div>

			<div className="max-h-80 overflow-y-auto">
				{isLoading ? (
					<div className="space-y-2 p-3">
						{Array.from({ length: 3 }).map((_, i) => (
							<Skeleton key={i} className="h-14 w-full" />
						))}
					</div>
				) : notifications.length === 0 ? (
					<p className="py-8 text-center text-sm text-muted-foreground">
						No notifications
					</p>
				) : (
					notifications.map((notification) => (
						<button
							type="button"
							key={notification.id}
							className={`w-full text-left px-4 py-3 hover:bg-muted/50 transition-colors ${
								!notification.read ? "bg-muted/30" : ""
							}`}
							onClick={() => {
								if (!notification.read) {
									markReadMutation.mutate(notification.id);
								}
								if (notification.actionUrl) {
									resolveActionMutation.mutate(notification.id);
								}
							}}
						>
							<div className="flex items-start gap-2">
								{!notification.read && (
									<span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-primary" />
								)}
								<div className="flex-1 min-w-0">
									<p className="text-sm font-medium truncate">
										{notification.title}
									</p>
									<p className="text-xs text-muted-foreground line-clamp-2">
										{notification.body}
									</p>
									<p className="mt-1 text-xs text-muted-foreground">
										{timeAgo(notification.createdAt)}
									</p>
								</div>
							</div>
						</button>
					))
				)}
			</div>

			<Separator />
			<div className="p-2">
				<Button
					variant="ghost"
					size="sm"
					className="w-full text-xs"
					nativeButton={false}
					render={<Link href="/notifications" />}
					onClick={onClose}
				>
					View all notifications
				</Button>
			</div>
		</div>
	);
}
