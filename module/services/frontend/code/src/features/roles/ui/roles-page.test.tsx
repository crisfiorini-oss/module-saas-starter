import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
	act,
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { OrgRole, PlatformRole } from "@/lib/auth-session";
import { renderInApp, rpc } from "@/test/container";
import { server } from "@/test/setup";
import { RolesPage } from "./roles-page";

const session = vi.hoisted(() => ({
	organizationId: "org-1" as string | undefined,
	orgRole: "owner" as OrgRole | undefined,
	platformRole: undefined as PlatformRole | undefined,
	switchOrganization: vi.fn(async () => undefined),
}));

vi.mock("@/lib/auth", () => ({ useAuth: () => session }));

beforeEach(() => {
	session.organizationId = "org-1";
	session.orgRole = "owner";
	session.platformRole = undefined;
	session.switchOrganization.mockReset();
});

afterEach(cleanup);

async function openDraft(name = "Example editor") {
	fireEvent.click(screen.getByRole("button", { name: "Create Role" }));
	await screen.findByRole("dialog");
	fireEvent.change(screen.getByLabelText("Name"), { target: { value: name } });
}

describe("RolesPage admin container", () => {
	it("renders the roles the permission service returns", async () => {
		const listedScopes: unknown[] = [];
		server.use(
			http.post(rpc("PermissionService", "ListRoles"), async ({ request }) => {
				listedScopes.push(await request.json());
				return HttpResponse.json({
					roles: [
						{
							id: "role-1",
							name: "Editor",
							description: "Can edit content",
							permissions: [{ resource: "content", action: "write" }],
							builtIn: false,
						},
					],
				});
			}),
		);

		renderInApp(<RolesPage />);

		expect(await screen.findByText("Editor")).toBeTruthy();
		expect(screen.getByText("content:write")).toBeTruthy();
		expect(listedScopes).toEqual([{ orgId: "org-1" }]);
	});

	it("shows the empty state when no roles are defined", async () => {
		renderInApp(<RolesPage />);

		expect(await screen.findByText("No roles defined")).toBeTruthy();
	});

	it.each(["owner", "admin"] as const)(
		"creates an organization role as an org %s without a platform role",
		async (orgRole) => {
			session.orgRole = orgRole;
			const requests: unknown[] = [];
			server.use(
				http.post(
					rpc("PermissionService", "CreateRole"),
					async ({ request }) => {
						requests.push(await request.json());
						return HttpResponse.json({ role: { id: "role-new" } });
					},
				),
			);
			renderInApp(<RolesPage />);
			await openDraft("  Example editor  ");
			fireEvent.change(screen.getByLabelText("Description"), {
				target: { value: "  Limited editing  " },
			});
			for (const action of ["read", "write"]) {
				fireEvent.change(screen.getByPlaceholderText("Resource"), {
					target: { value: "content" },
				});
				fireEvent.change(screen.getByPlaceholderText("Action"), {
					target: { value: action },
				});
				fireEvent.click(screen.getByRole("button", { name: "Add" }));
			}
			fireEvent.click(screen.getByRole("button", { name: "Create" }));
			await waitFor(() =>
				expect(requests).toEqual([
					{
						orgId: "org-1",
						name: "Example editor",
						description: "Limited editing",
						permissions: [
							{ resource: "content", action: "read" },
							{ resource: "content", action: "write" },
						],
					},
				]),
			);
			await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
		},
	);

	it.each([
		{ organizationId: undefined, orgRole: "owner", platformRole: undefined },
		{ organizationId: "org-1", orgRole: "member", platformRole: undefined },
		{ organizationId: undefined, orgRole: undefined, platformRole: "support" },
	] as const)(
		"does not offer creation without authority for the current scope: %j",
		(auth) => {
			Object.assign(session, auth);
			renderInApp(<RolesPage />);
			expect(screen.queryByRole("button", { name: "Create Role" })).toBeNull();
		},
	);

	it("preserves explicit global creation for a platform admin without an organization", async () => {
		session.organizationId = undefined;
		session.orgRole = undefined;
		session.platformRole = "super_admin";
		const requests: Record<string, unknown>[] = [];
		server.use(
			http.post(rpc("PermissionService", "CreateRole"), async ({ request }) => {
				requests.push((await request.json()) as Record<string, unknown>);
				return HttpResponse.json({ role: { id: "role-global" } });
			}),
		);
		renderInApp(<RolesPage />);
		await openDraft();
		expect(
			screen.getByText("Define a global role with custom permissions."),
		).toBeTruthy();
		fireEvent.click(screen.getByRole("button", { name: "Create" }));
		await waitFor(() => expect(requests).toHaveLength(1));
		// Protobuf JSON omits default-valued empty strings.
		expect(requests[0].orgId ?? "").toBe("");
	});

	it("closes and clears an open draft when the authenticated organization changes", async () => {
		const listedScopes: unknown[] = [];
		const createdScopes: unknown[] = [];
		server.use(
			http.post(rpc("PermissionService", "ListRoles"), async ({ request }) => {
				listedScopes.push(await request.json());
				return HttpResponse.json({ roles: [] });
			}),
			http.post(rpc("PermissionService", "CreateRole"), async ({ request }) => {
				createdScopes.push(await request.json());
				return HttpResponse.json({ role: { id: "role-new" } });
			}),
		);
		const client = new QueryClient({
			defaultOptions: { queries: { retry: false } },
		});
		const view = render(<RolesPage />, {
			wrapper: ({ children }) => (
				<QueryClientProvider client={client}>{children}</QueryClientProvider>
			),
		});
		await openDraft("First organization draft");
		fireEvent.change(screen.getByPlaceholderText("Resource"), {
			target: { value: "content" },
		});
		fireEvent.change(screen.getByPlaceholderText("Action"), {
			target: { value: "write" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Add" }));
		await waitFor(() =>
			expect(listedScopes).toContainEqual({ orgId: "org-1" }),
		);
		session.organizationId = "org-2";
		view.rerender(<RolesPage />);
		expect(screen.queryByRole("dialog")).toBeNull();
		await waitFor(() =>
			expect(listedScopes).toContainEqual({ orgId: "org-2" }),
		);
		fireEvent.click(screen.getByRole("button", { name: "Create Role" }));
		await screen.findByRole("dialog");
		expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("");
		expect(screen.queryByText("content:write")).toBeNull();
		fireEvent.change(screen.getByLabelText("Name"), {
			target: { value: "Second organization role" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create" }));
		await waitFor(() =>
			expect(createdScopes).toEqual([
				{
					orgId: "org-2",
					name: "Second organization role",
				},
			]),
		);
	});

	it("keeps the draft open when the authenticated API refuses creation", async () => {
		let refused = false;
		server.use(
			http.post(rpc("PermissionService", "CreateRole"), () => {
				refused = true;
				return HttpResponse.json(
					{ code: "permission_denied", message: "Not authorized" },
					{ status: 403 },
				);
			}),
		);
		renderInApp(<RolesPage />);
		await openDraft();
		fireEvent.click(screen.getByRole("button", { name: "Create" }));
		await waitFor(() => expect(refused).toBe(true));
		await waitFor(() =>
			expect(
				screen.getByRole("button", { name: "Create" }).hasAttribute("disabled"),
			).toBe(false),
		);
		expect(screen.getByRole("dialog")).toBeTruthy();
		expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe(
			"Example editor",
		);
	});

	it("keeps a draft bound to the original organization when switching fails", async () => {
		let rejectSwitch!: (error: Error) => void;
		session.switchOrganization.mockImplementationOnce(
			() =>
				new Promise<undefined>((_resolve, reject) => {
					rejectSwitch = reject;
				}),
		);
		const requests: unknown[] = [];
		server.use(
			http.post(rpc("OrganizationService", "ListOrganizations"), () =>
				HttpResponse.json({
					organizations: [
						{ id: "org-1", name: "Example One" },
						{ id: "org-2", name: "Example Two" },
					],
				}),
			),
			http.post(rpc("PermissionService", "CreateRole"), async ({ request }) => {
				requests.push(await request.json());
				return HttpResponse.json({ role: { id: "role-new" } });
			}),
		);
		renderInApp(<RolesPage />);
		await waitFor(() =>
			expect(screen.getByRole("combobox").hasAttribute("disabled")).toBe(false),
		);
		fireEvent.click(screen.getByRole("combobox"));
		const option = await screen.findByRole("option", { name: "Example Two" });
		fireEvent.pointerDown(option, { pointerType: "mouse" });
		fireEvent.click(option);
		await waitFor(() =>
			expect(session.switchOrganization).toHaveBeenCalledWith("org-2"),
		);
		await openDraft("Original organization role");
		await act(async () => {
			rejectSwitch(new Error("Organization switch refused"));
		});
		expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe(
			"Original organization role",
		);
		fireEvent.click(screen.getByRole("button", { name: "Create" }));
		await waitFor(() =>
			expect(requests).toEqual([
				{ orgId: "org-1", name: "Original organization role" },
			]),
		);
	});
});
