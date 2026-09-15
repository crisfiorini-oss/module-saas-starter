import { Code, ConnectError } from "@connectrpc/connect";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	markRead: vi.fn(async () => undefined),
	resolveAction: vi.fn(async (_id: string) => "/invitations/accept?token=token"),
	push: vi.fn(),
	error: vi.fn(),
}));

vi.mock("sonner", () => ({
	toast: { success: vi.fn(), error: mocks.error },
}));

vi.mock("next/navigation", () => ({
	useRouter: () => ({ push: mocks.push }),
}));

vi.mock("../service/queries", () => ({
	notificationQueries: {
		list: () => ({
			queryKey: ["notifications"],
			queryFn: async () => ({
				notifications: [
					{
						id: "notification-1",
						title: "You've been invited",
						body: "Join Acme",
						type: "info",
						read: false,
						createdAt: "2026-07-28T12:34:56.789Z",
						actionUrl: "/invitations/accept?token=token",
					},
				],
				nextPageToken: "",
			}),
		}),
	},
}));

vi.mock("../service/mutations", () => ({
	notificationMutations: {
		markRead: mocks.markRead,
		resolveAction: mocks.resolveAction,
		markAllRead: vi.fn(async () => undefined),
	},
}));

import { NotificationPanel } from "./notification-panel";

afterEach(() => {
	cleanup();
	mocks.markRead.mockClear();
	mocks.resolveAction.mockClear();
	mocks.push.mockClear();
	mocks.error.mockClear();
	mocks.resolveAction.mockResolvedValue("/invitations/accept?token=token");
});

function renderPanel(onClose = vi.fn()) {
	const queryClient = new QueryClient({
		defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
	});
	render(
		<QueryClientProvider client={queryClient}>
			<NotificationPanel onClose={onClose} />
		</QueryClientProvider>,
	);
	return onClose;
}

describe("NotificationPanel", () => {
	// The stored URL is never pushed directly: the destination comes back from
	// the server, which re-authorizes the resource as the link is followed.
	it("marks an actionable notification read and opens the re-authorized destination", async () => {
		const onClose = renderPanel();

		fireEvent.click(
			await screen.findByRole("button", {
				name: /You've been invited/,
			}),
		);

		await waitFor(() => {
			expect(mocks.markRead).toHaveBeenCalledWith("notification-1");
		});
		await waitFor(() => {
			expect(mocks.push).toHaveBeenCalledWith("/invitations/accept?token=token");
		});
		expect(mocks.resolveAction).toHaveBeenCalledWith("notification-1");
		expect(onClose).toHaveBeenCalledOnce();
	});

	// A link followed after the grant was revoked resolves to NOT_FOUND. The
	// panel must not fall back to the URL it still holds in the cached item.
	it("does not navigate when the destination no longer resolves", async () => {
		mocks.resolveAction.mockRejectedValue(
			new ConnectError("notification not found", Code.NotFound),
		);
		const onClose = renderPanel();

		fireEvent.click(
			await screen.findByRole("button", {
				name: /You've been invited/,
			}),
		);

		await waitFor(() => {
			expect(mocks.error).toHaveBeenCalled();
		});
		expect(mocks.push).not.toHaveBeenCalled();
		expect(onClose).not.toHaveBeenCalled();
	});
});
