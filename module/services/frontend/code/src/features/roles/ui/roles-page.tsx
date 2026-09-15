"use client";

import { OrgSelector } from "@/components/org-selector";
import { PERMISSIONS } from "@/gen/saas/accounts/v1/frontend_catalog";
import { useAuth } from "@/lib/auth";
import { hasPermission, isSuperAdmin } from "@/lib/permissions";
import type { Role } from "../model/types";
import { useRoles } from "../service/queries";
import { RoleForm } from "./role-form";
import { RolesTable } from "./roles-table";

export function RolesPage() {
	const { organizationId: orgId = "", platformRole, orgRole } = useAuth();
	const canCreate = orgId
		? hasPermission(platformRole, orgRole, PERMISSIONS.ROLES_WRITE)
		: isSuperAdmin(platformRole);

	// A tenant switch closes any open draft instead of silently retargeting it.
	return (
		<RolesPageForOrganization key={orgId} orgId={orgId} canCreate={canCreate} />
	);
}

function RolesPageForOrganization({
	orgId,
	canCreate,
}: {
	orgId: string;
	canCreate: boolean;
}) {
	const { data: roles = [], isLoading } = useRoles(orgId);

	return (
		<div className="space-y-6">
			<div className="flex items-center justify-between">
				<div>
					<h1 className="text-2xl font-bold tracking-tight">Roles</h1>
					<p className="text-muted-foreground">
						{orgId
							? "Manage roles and permissions for the selected organization."
							: "Global roles. Select an organization to manage its roles."}
					</p>
				</div>
				<div className="flex items-center gap-3">
					<OrgSelector />
					{canCreate && <RoleForm orgId={orgId} />}
				</div>
			</div>

			<RolesTable roles={roles as Role[]} isLoading={isLoading} />
		</div>
	);
}
