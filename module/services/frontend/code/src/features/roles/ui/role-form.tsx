"use client";

import { Plus, X } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import {
	Badge,
	Button,
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
	DialogTrigger,
	Input,
	Label,
} from "@/shared/ui";
import { useCreateRole } from "../service/mutations";

export function RoleForm({ orgId }: { orgId: string }) {
	const [open, setOpen] = useState(false);
	const [name, setName] = useState("");
	const [description, setDescription] = useState("");
	const [permResource, setPermResource] = useState("");
	const [permAction, setPermAction] = useState("");
	const [permissions, setPermissions] = useState<
		{ resource: string; action: string }[]
	>([]);

	const createRole = useCreateRole();

	function addPermission() {
		if (!permResource.trim() || !permAction.trim()) return;
		setPermissions((prev) => [
			...prev,
			{ resource: permResource.trim(), action: permAction.trim() },
		]);
		setPermResource("");
		setPermAction("");
	}

	function removePermission(index: number) {
		setPermissions((prev) => prev.filter((_, i) => i !== index));
	}

	function reset() {
		setName("");
		setDescription("");
		setPermissions([]);
		setPermResource("");
		setPermAction("");
	}

	function handleSubmit() {
		if (!name.trim()) return;
		createRole.mutate(
			{
				name: name.trim(),
				description: description.trim(),
				permissions,
				orgId,
			},
			{
				onSuccess: () => {
					toast.success(`Role "${name.trim()}" created`);
					reset();
					setOpen(false);
				},
				onError: () => toast.error("Failed to create role"),
			},
		);
	}

	return (
		<Dialog open={open} onOpenChange={setOpen}>
			<DialogTrigger render={<Button />}>
				<Plus className="mr-2 h-4 w-4" />
				Create Role
			</DialogTrigger>
			<DialogContent className="sm:max-w-lg">
				<DialogHeader>
					<DialogTitle>Create Role</DialogTitle>
					<DialogDescription>
						{orgId
							? "Define a role for the selected organization."
							: "Define a global role with custom permissions."}
					</DialogDescription>
				</DialogHeader>

				<div className="space-y-4 py-4">
					<div className="space-y-2">
						<Label htmlFor="role-name">Name</Label>
						<Input
							id="role-name"
							placeholder="e.g. billing-admin"
							value={name}
							onChange={(e) => setName(e.target.value)}
						/>
					</div>

					<div className="space-y-2">
						<Label htmlFor="role-desc">Description</Label>
						<Input
							id="role-desc"
							placeholder="Optional description"
							value={description}
							onChange={(e) => setDescription(e.target.value)}
						/>
					</div>

					<div className="space-y-2">
						<Label>Permissions</Label>
						{permissions.length > 0 && (
							<div className="flex flex-wrap gap-1">
								{permissions.map((p, i) => (
									<Badge
										key={i}
										variant="secondary"
										className="font-mono text-xs gap-1"
									>
										{p.resource}:{p.action}
										<button
											type="button"
											onClick={() => removePermission(i)}
											className="ml-1 hover:text-destructive"
										>
											<X className="h-3 w-3" />
										</button>
									</Badge>
								))}
							</div>
						)}
						<div className="flex items-center gap-2">
							<Input
								placeholder="Resource"
								value={permResource}
								onChange={(e) => setPermResource(e.target.value)}
								className="flex-1"
							/>
							<Input
								placeholder="Action"
								value={permAction}
								onChange={(e) => setPermAction(e.target.value)}
								onKeyDown={(e) => e.key === "Enter" && addPermission()}
								className="flex-1"
							/>
							<Button
								type="button"
								variant="outline"
								size="sm"
								onClick={addPermission}
								disabled={!permResource.trim() || !permAction.trim()}
							>
								Add
							</Button>
						</div>
					</div>
				</div>

				<DialogFooter>
					<Button
						variant="outline"
						onClick={() => {
							reset();
							setOpen(false);
						}}
					>
						Cancel
					</Button>
					<Button
						onClick={handleSubmit}
						disabled={createRole.isPending || !name.trim()}
					>
						{createRole.isPending ? "Creating..." : "Create"}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}
