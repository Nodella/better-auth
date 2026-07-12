import type { AuthContext } from "@better-auth/core";
import { APIError, BASE_ERROR_CODES } from "@better-auth/core/error";
import * as z from "zod";
import type { User } from "../../types";
import { defaultRoles } from "./access";
import { getOrgAdapter, resolveMaximumMembersPerTeam } from "./adapter";
import { ORGANIZATION_ERROR_CODES } from "./error-codes";
import type {
	InferInvitation,
	InferMember,
	InferOrganization,
	InferTeam,
	Invitation,
	Member,
	Organization,
	Team,
} from "./schema";
import type { OrganizationOptions } from "./types";

export type OrganizationServerRun = <Result>(
	fn: (ctx: AuthContext) => Result | Promise<Result>,
) => Promise<Result>;

type ServerUser = User & Record<string, unknown>;
type ServerOrganization = Organization & Record<string, unknown>;
type ServerMember = Member & Record<string, unknown>;
type ServerInvitation = Invitation & Record<string, unknown>;
type ServerTeam = Team & Record<string, unknown>;

type ServerMemberRow<O extends OrganizationOptions> = Member &
	(O["teams"] extends { enabled: true }
		? { teamId?: string | undefined }
		: {}) &
	Record<string, unknown>;

type OrganizationAdapter<O extends OrganizationOptions> = ReturnType<
	typeof getOrgAdapter<O>
>;
type ListMembersResult<O extends OrganizationOptions> = Awaited<
	ReturnType<OrganizationAdapter<O>["listMembers"]>
>;
type ServerFullOrganization<O extends OrganizationOptions> =
	InferOrganization<O> & {
		members: Array<
			ServerMemberRow<O> & {
				user: Pick<User, "id" | "name" | "email" | "image">;
			}
		>;
		invitations: InferInvitation<O>[];
		teams?: InferTeam<O>[] | undefined;
	};

type CreateOrganizationInput = {
	userId: string;
	name: string;
	slug: string;
	logo?: string | null | undefined;
	metadata?: Record<string, unknown> | undefined;
	data?: Record<string, unknown> | undefined;
};

type UpdateOrganizationInput = {
	organizationId: string;
	userId?: string | undefined;
	data: {
		name?: string | undefined;
		slug?: string | undefined;
		logo?: string | null | undefined;
		metadata?: Record<string, unknown> | undefined;
		[key: string]: unknown;
	};
};

type OrganizationIdInput = {
	organizationId: string;
};

type ListForUserInput = {
	userId: string;
};

type ListMembersInput = OrganizationIdInput & {
	limit?: number | undefined;
	offset?: number | undefined;
	sortBy?: string | undefined;
	sortOrder?: "asc" | "desc" | undefined;
	filter?:
		| {
				field: string;
				operator?: "eq" | "ne" | "lt" | "lte" | "gt" | "gte" | "in";
				value: unknown;
		  }
		| undefined;
};

type AddMemberInput = OrganizationIdInput & {
	userId: string;
	role: string | string[];
	teamId?: string | undefined;
	data?: Record<string, unknown> | undefined;
};

type RemoveMemberInput = OrganizationIdInput & {
	memberId: string;
};

type UpdateMemberInput = {
	memberId: string;
	role: string | string[];
};

type CreateInvitationInput = OrganizationIdInput & {
	email: string;
	role: string | string[];
	inviterId: string;
	teamId?: string | string[] | undefined;
	resend?: boolean | undefined;
	data?: Record<string, unknown> | undefined;
};

type CancelInvitationInput = {
	invitationId: string;
	cancelledById?: string | undefined;
};

type CreateTeamInput = OrganizationIdInput & {
	name: string;
	userId?: string | undefined;
	data?: Record<string, unknown> | undefined;
};

type GetTeamInput = {
	teamId: string;
	organizationId?: string | undefined;
	includeMembers?: boolean | undefined;
};

type UpdateTeamInput = {
	teamId: string;
	userId?: string | undefined;
	data: {
		name?: string | undefined;
		description?: string | undefined;
		status?: string | undefined;
		[key: string]: unknown;
	};
};

type DeleteTeamInput = {
	teamId: string;
	userId?: string | undefined;
};

type TeamServerAPI<O extends OrganizationOptions> = O["teams"] extends {
	enabled: true;
}
	? {
			createTeam: (input: CreateTeamInput) => Promise<InferTeam<O>>;
			getTeam: (input: GetTeamInput) => Promise<InferTeam<O> | null>;
			updateTeam: (input: UpdateTeamInput) => Promise<InferTeam<O>>;
			deleteTeam: (input: DeleteTeamInput) => Promise<InferTeam<O>>;
			listTeams: (
				input: OrganizationIdInput,
			) => Promise<{ teams: InferTeam<O>[] }>;
		}
	: {};

type OrganizationServerBaseAPI<O extends OrganizationOptions> = {
	createOrganization: (input: CreateOrganizationInput) => Promise<{
		organization: InferOrganization<O>;
		member: ServerMemberRow<O>;
		team?: InferTeam<O> | undefined;
	}>;
	getOrganization: (
		input: OrganizationIdInput,
	) => Promise<InferOrganization<O> | null>;
	getFullOrganization: (
		input: OrganizationIdInput & {
			includeTeams?: boolean | undefined;
			membersLimit?: number | undefined;
		},
	) => Promise<ServerFullOrganization<O> | null>;
	updateOrganization: (
		input: UpdateOrganizationInput,
	) => Promise<InferOrganization<O>>;
	deleteOrganization: (
		input: OrganizationIdInput & { userId?: string | undefined },
	) => Promise<InferOrganization<O>>;
	listForUser: (input: ListForUserInput) => Promise<{
		organizations: InferOrganization<O>[];
	}>;
	addMember: (input: AddMemberInput) => Promise<ServerMemberRow<O>>;
	removeMember: (
		input: RemoveMemberInput,
	) => Promise<{ member: ServerMemberRow<O> }>;
	updateMember: (input: UpdateMemberInput) => Promise<ServerMemberRow<O>>;
	listMembers: (input: ListMembersInput) => Promise<ListMembersResult<O>>;
	createInvitation: (
		input: CreateInvitationInput,
	) => Promise<{ invitation: InferInvitation<O> }>;
	listInvitations: (
		input: OrganizationIdInput,
	) => Promise<{ invitations: InferInvitation<O>[] }>;
	cancelInvitation: (
		input: CancelInvitationInput,
	) => Promise<{ invitation: InferInvitation<O> }>;
};

export type OrganizationServerAPI<O extends OrganizationOptions> =
	OrganizationServerBaseAPI<O> & TeamServerAPI<O>;

export type OrganizationServerPlugin<O extends OrganizationOptions> = {
	server: (
		ctx: Promise<AuthContext>,
		helpers: {
			run: OrganizationServerRun;
		},
	) => { organization: OrganizationServerAPI<O> };
};

function parseRoles(roles: string | string[]): string {
	return Array.isArray(roles) ? roles.join(",") : roles;
}

function asHookUser(user: User): ServerUser {
	return user as ServerUser;
}

function asHookOrganization<O extends OrganizationOptions>(
	organization: InferOrganization<O>,
): ServerOrganization {
	return organization as ServerOrganization;
}

function asHookMember<O extends OrganizationOptions>(
	member: ServerMemberRow<O> | InferMember<O>,
): ServerMember {
	return member as ServerMember;
}

function asHookInvitation<O extends OrganizationOptions>(
	invitation: InferInvitation<O>,
): ServerInvitation {
	return invitation as ServerInvitation;
}

function asHookTeam<O extends OrganizationOptions>(
	team: InferTeam<O>,
): ServerTeam {
	return team as ServerTeam;
}

async function requireUser(ctx: AuthContext, userId: string): Promise<User> {
	const user = await ctx.internalAdapter.findUserById(userId);
	if (!user) {
		throw APIError.from("NOT_FOUND", BASE_ERROR_CODES.USER_NOT_FOUND);
	}
	return user;
}

async function validateRoles<O extends OrganizationOptions>(
	ctx: AuthContext,
	options: O,
	organizationId: string,
	role: string | string[],
): Promise<string> {
	const roles = parseRoles(role);
	const rolesArray = roles
		.split(",")
		.map((item) => item.trim())
		.filter(Boolean);
	const staticRoles = new Set([
		...Object.keys(defaultRoles),
		...Object.keys(options.roles || {}),
	]);
	const unknownRoles = rolesArray.filter((item) => !staticRoles.has(item));
	if (!unknownRoles.length) {
		return roles;
	}
	if (options.dynamicAccessControl?.enabled) {
		const foundRoles = await ctx.adapter.findMany<{ role: string }>({
			model: "organizationRole",
			where: [
				{ field: "organizationId", value: organizationId },
				{ field: "role", value: unknownRoles, operator: "in" },
			],
		});
		const foundRoleNames = foundRoles.map((item) => item.role);
		const stillInvalid = unknownRoles.filter(
			(item) => !foundRoleNames.includes(item),
		);
		if (!stillInvalid.length) {
			return roles;
		}
		throw new APIError("BAD_REQUEST", {
			message: `${ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND}: ${stillInvalid.join(", ")}`,
		});
	}
	throw new APIError("BAD_REQUEST", {
		message: `${ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND}: ${unknownRoles.join(", ")}`,
	});
}

async function requireOrganization<O extends OrganizationOptions>(
	ctx: AuthContext,
	options: O,
	organizationId: string,
): Promise<InferOrganization<O>> {
	const adapter = getOrgAdapter<O>(ctx, options);
	const organization = await adapter.findOrganizationById(organizationId);
	if (!organization) {
		throw APIError.from(
			"BAD_REQUEST",
			ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
		);
	}
	return organization;
}

export function createOrganizationServerAPI<O extends OrganizationOptions>(
	options: O,
	run: OrganizationServerRun,
): OrganizationServerAPI<O> {
	const api: OrganizationServerBaseAPI<O> = {
		createOrganization: async ({
			userId,
			name,
			slug,
			logo,
			metadata,
			data,
		}) => {
			return await run(async (ctx) => {
				const user = await requireUser(ctx, userId);
				const adapter = getOrgAdapter<O>(ctx, options);
				const userOrganizations = await adapter.listOrganizations(user.id);
				const hasReachedOrgLimit =
					typeof options.organizationLimit === "number"
						? userOrganizations.length >= options.organizationLimit
						: typeof options.organizationLimit === "function"
							? await options.organizationLimit(asHookUser(user))
							: false;
				if (hasReachedOrgLimit) {
					throw APIError.from(
						"FORBIDDEN",
						ORGANIZATION_ERROR_CODES.YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS,
					);
				}
				const existingOrganization = await adapter.findOrganizationBySlug(slug);
				if (existingOrganization) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.ORGANIZATION_ALREADY_EXISTS,
					);
				}

				let organizationData = {
					...(data || {}),
					name,
					slug,
					...(logo !== undefined ? { logo } : {}),
					...(metadata !== undefined ? { metadata } : {}),
				};
				if (options.organizationHooks?.beforeCreateOrganization) {
					const response =
						await options.organizationHooks.beforeCreateOrganization({
							organization: organizationData,
							user: asHookUser(user),
						});
					if (response && typeof response === "object" && "data" in response) {
						organizationData = {
							...organizationData,
							...response.data,
						};
					}
				}
				const organization = await adapter.createOrganization({
					organization: {
						...organizationData,
						createdAt: new Date(),
					},
				});

				let memberData = {
					userId: user.id,
					organizationId: organization.id,
					role: options.creatorRole || "owner",
				};
				if (options.organizationHooks?.beforeAddMember) {
					const response = await options.organizationHooks.beforeAddMember({
						member: memberData,
						user: asHookUser(user),
						organization: asHookOrganization(organization),
					});
					if (response && typeof response === "object" && "data" in response) {
						memberData = {
							...memberData,
							...response.data,
						};
					}
				}
				const member = await adapter.createMember(memberData);
				if (options.organizationHooks?.afterAddMember) {
					await options.organizationHooks.afterAddMember({
						member: asHookMember(member),
						user: asHookUser(user),
						organization: asHookOrganization(organization),
					});
				}

				let team: InferTeam<O> | undefined;
				if (
					options.teams?.enabled &&
					options.teams.defaultTeam?.enabled !== false
				) {
					let teamData = {
						organizationId: organization.id,
						name: organization.name,
						createdAt: new Date(),
					};
					if (options.organizationHooks?.beforeCreateTeam) {
						const response = await options.organizationHooks.beforeCreateTeam({
							team: {
								organizationId: organization.id,
								name: organization.name,
							},
							user: asHookUser(user),
							organization: asHookOrganization(organization),
						});
						if (
							response &&
							typeof response === "object" &&
							"data" in response
						) {
							teamData = {
								...teamData,
								...response.data,
							};
						}
					}
					team =
						((await options.teams.defaultTeam?.customCreateDefaultTeam?.(
							asHookOrganization(organization),
						)) as InferTeam<O> | undefined) ||
						(await adapter.createTeam(teamData));
					await adapter.findOrCreateTeamMember({
						teamId: team.id,
						userId: user.id,
					});
					if (options.organizationHooks?.afterCreateTeam) {
						await options.organizationHooks.afterCreateTeam({
							team: asHookTeam(team),
							user: asHookUser(user),
							organization: asHookOrganization(organization),
						});
					}
				}

				if (options.organizationHooks?.afterCreateOrganization) {
					await options.organizationHooks.afterCreateOrganization({
						organization: asHookOrganization(organization),
						member: asHookMember(member),
						user: asHookUser(user),
					});
				}
				return {
					organization,
					member,
					...(team ? { team } : {}),
				};
			});
		},
		getOrganization: async ({ organizationId }) => {
			return await run(async (ctx) => {
				const adapter = getOrgAdapter<O>(ctx, options);
				return await adapter.findOrganizationById(organizationId);
			});
		},
		getFullOrganization: async ({
			organizationId,
			includeTeams,
			membersLimit,
		}) => {
			return await run(async (ctx) => {
				const adapter = getOrgAdapter<O>(ctx, options);
				return (await adapter.findFullOrganization({
					organizationId,
					includeTeams,
					membersLimit,
				})) as ServerFullOrganization<O> | null;
			});
		},
		updateOrganization: async ({ organizationId, userId, data }) => {
			return await run(async (ctx) => {
				const adapter = getOrgAdapter<O>(ctx, options);
				const organization = await requireOrganization(
					ctx,
					options,
					organizationId,
				);
				if (typeof data.slug === "string") {
					const existingOrganization = await adapter.findOrganizationBySlug(
						data.slug,
					);
					if (
						existingOrganization &&
						existingOrganization.id !== organizationId
					) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.ORGANIZATION_SLUG_ALREADY_TAKEN,
						);
					}
				}

				let updateData = { ...data };
				let user: User | undefined;
				let member: ServerMember | undefined;
				if (userId) {
					user = await requireUser(ctx, userId);
					const foundMember = await adapter.findMemberByOrgId({
						userId,
						organizationId,
					});
					if (!foundMember) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
						);
					}
					member = foundMember;
				}
				if (
					user &&
					member &&
					options.organizationHooks?.beforeUpdateOrganization
				) {
					const response =
						await options.organizationHooks.beforeUpdateOrganization({
							organization: updateData,
							user: asHookUser(user),
							member: asHookMember(member),
						});
					if (response && typeof response === "object" && "data" in response) {
						updateData = {
							...updateData,
							...response.data,
						};
					}
				}
				const updatedOrganization = await adapter.updateOrganization(
					organization.id,
					updateData,
				);
				if (!updatedOrganization) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
					);
				}
				if (
					user &&
					member &&
					options.organizationHooks?.afterUpdateOrganization
				) {
					await options.organizationHooks.afterUpdateOrganization({
						organization: asHookOrganization(updatedOrganization),
						user: asHookUser(user),
						member: asHookMember(member),
					});
				}
				return updatedOrganization;
			});
		},
		deleteOrganization: async ({ organizationId, userId }) => {
			return await run(async (ctx) => {
				if (options.disableOrganizationDeletion) {
					throw APIError.from("NOT_FOUND", {
						message: "Organization deletion is disabled",
						code: "ORGANIZATION_DELETION_DISABLED",
					});
				}
				const adapter = getOrgAdapter<O>(ctx, options);
				const organization = await requireOrganization(
					ctx,
					options,
					organizationId,
				);
				const user = userId ? await requireUser(ctx, userId) : undefined;
				if (user && options.organizationHooks?.beforeDeleteOrganization) {
					await options.organizationHooks.beforeDeleteOrganization({
						organization: asHookOrganization(organization),
						user: asHookUser(user),
					});
				}
				await adapter.deleteOrganization(organizationId);
				if (user && options.organizationHooks?.afterDeleteOrganization) {
					await options.organizationHooks.afterDeleteOrganization({
						organization: asHookOrganization(organization),
						user: asHookUser(user),
					});
				}
				return organization;
			});
		},
		listForUser: async ({ userId }) => {
			return await run(async (ctx) => {
				await requireUser(ctx, userId);
				const adapter = getOrgAdapter<O>(ctx, options);
				return {
					organizations: await adapter.listOrganizations(userId),
				};
			});
		},
		addMember: async ({ organizationId, userId, role, teamId, data }) => {
			return await run(async (ctx) => {
				const user = await requireUser(ctx, userId);
				const organization = await requireOrganization(
					ctx,
					options,
					organizationId,
				);
				const adapter = getOrgAdapter<O>(ctx, options);
				const existingMember = await adapter.findMemberByOrgId({
					userId,
					organizationId,
				});
				if (existingMember) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION,
					);
				}

				const membershipLimit = options.membershipLimit ?? 100;
				const limit =
					typeof membershipLimit === "number"
						? membershipLimit
						: await membershipLimit(user, organization);
				const count = await adapter.countMembers({ organizationId });
				if (count >= limit) {
					throw APIError.from(
						"FORBIDDEN",
						ORGANIZATION_ERROR_CODES.ORGANIZATION_MEMBERSHIP_LIMIT_REACHED,
					);
				}

				if (teamId) {
					const team = await adapter.findTeamById({
						teamId,
						organizationId,
					});
					if (!team) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
						);
					}
				}

				const parsedRole = await validateRoles(
					ctx,
					options,
					organizationId,
					role,
				);
				let memberData = {
					...(data || {}),
					organizationId,
					userId,
					role: parsedRole,
					createdAt: new Date(),
				};
				if (options.organizationHooks?.beforeAddMember) {
					const response = await options.organizationHooks.beforeAddMember({
						member: memberData,
						user: asHookUser(user),
						organization: asHookOrganization(organization),
					});
					if (response && typeof response === "object" && "data" in response) {
						memberData = {
							...memberData,
							...response.data,
						};
					}
				}

				if (teamId) {
					const maximumMembersPerTeam = await resolveMaximumMembersPerTeam(
						options.teams,
						{
							teamId,
							organizationId,
							session: null,
						},
					);
					if (maximumMembersPerTeam !== undefined) {
						const result = await adapter.addTeamMemberWithLimit({
							teamId,
							userId,
							maximumMembersPerTeam,
						});
						if (result.status === "limitReached") {
							throw APIError.from(
								"FORBIDDEN",
								ORGANIZATION_ERROR_CODES.TEAM_MEMBER_LIMIT_REACHED,
							);
						}
					} else {
						await adapter.findOrCreateTeamMember({
							teamId,
							userId,
						});
					}
				}

				const member = await adapter.createMember(memberData);
				if (options.organizationHooks?.afterAddMember) {
					await options.organizationHooks.afterAddMember({
						member: asHookMember(member),
						user: asHookUser(user),
						organization: asHookOrganization(organization),
					});
				}
				return member;
			});
		},
		removeMember: async ({ organizationId, memberId }) => {
			return await run(async (ctx) => {
				const adapter = getOrgAdapter<O>(ctx, options);
				const member = await adapter.findMemberById(memberId);
				if (!member || member.organizationId !== organizationId) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
					);
				}
				const organization = await requireOrganization(
					ctx,
					options,
					organizationId,
				);
				const user = await requireUser(ctx, member.userId);
				if (options.organizationHooks?.beforeRemoveMember) {
					await options.organizationHooks.beforeRemoveMember({
						member: asHookMember(member),
						user: asHookUser(user),
						organization: asHookOrganization(organization),
					});
				}
				await adapter.deleteMember({
					memberId,
					organizationId,
					userId: member.userId,
				});
				if (options.organizationHooks?.afterRemoveMember) {
					await options.organizationHooks.afterRemoveMember({
						member: asHookMember(member),
						user: asHookUser(user),
						organization: asHookOrganization(organization),
					});
				}
				return { member };
			});
		},
		updateMember: async ({ memberId, role }) => {
			return await run(async (ctx) => {
				const adapter = getOrgAdapter<O>(ctx, options);
				const member = await adapter.findMemberById(memberId);
				if (!member) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
					);
				}
				const organization = await requireOrganization(
					ctx,
					options,
					member.organizationId,
				);
				const user = await requireUser(ctx, member.userId);
				const previousRole = member.role;
				let newRole = await validateRoles(
					ctx,
					options,
					member.organizationId,
					role,
				);
				if (options.organizationHooks?.beforeUpdateMemberRole) {
					const response =
						await options.organizationHooks.beforeUpdateMemberRole({
							member: asHookMember(member),
							newRole,
							user: asHookUser(user),
							organization: asHookOrganization(organization),
						});
					if (response && typeof response === "object" && "data" in response) {
						newRole = response.data.role || newRole;
					}
				}
				const updatedMember = await adapter.updateMember(memberId, newRole);
				if (!updatedMember) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
					);
				}
				if (options.organizationHooks?.afterUpdateMemberRole) {
					await options.organizationHooks.afterUpdateMemberRole({
						member: asHookMember(updatedMember),
						previousRole,
						user: asHookUser(user),
						organization: asHookOrganization(organization),
					});
				}
				return updatedMember;
			});
		},
		listMembers: async (input) => {
			return await run(async (ctx) => {
				const adapter = getOrgAdapter<O>(ctx, options);
				await requireOrganization(ctx, options, input.organizationId);
				return await adapter.listMembers(input);
			});
		},
		createInvitation: async ({
			organizationId,
			email,
			role,
			inviterId,
			teamId,
			resend,
			data,
		}) => {
			return await run(async (ctx) => {
				const normalizedEmail = email.toLowerCase();
				if (!z.email().safeParse(normalizedEmail).success) {
					throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_EMAIL);
				}
				const inviter = await requireUser(ctx, inviterId);
				const adapter = getOrgAdapter<O>(ctx, options);
				const member = await adapter.findMemberByOrgId({
					userId: inviterId,
					organizationId,
				});
				if (!member) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
					);
				}
				const organization = await requireOrganization(
					ctx,
					options,
					organizationId,
				);
				const roles = await validateRoles(ctx, options, organizationId, role);
				const alreadyMember = await adapter.findMemberByEmail({
					email: normalizedEmail,
					organizationId,
				});
				if (alreadyMember) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION,
					);
				}
				const pendingInvitations = await adapter.findPendingInvitation({
					email: normalizedEmail,
					organizationId,
				});
				if (
					pendingInvitations.length &&
					!resend &&
					!options.cancelPendingInvitationsOnReInvite
				) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION,
					);
				}
				if (pendingInvitations.length && resend) {
					return {
						invitation: pendingInvitations[0]!,
					};
				}
				if (
					pendingInvitations.length &&
					options.cancelPendingInvitationsOnReInvite
				) {
					await adapter.updateInvitation({
						invitationId: pendingInvitations[0]!.id,
						status: "canceled",
					});
				}

				const invitationLimit =
					typeof options.invitationLimit === "function"
						? await options.invitationLimit(
								{
									user: asHookUser(inviter),
									organization: asHookOrganization(organization),
									member: asHookMember(member),
								},
								ctx,
							)
						: (options.invitationLimit ?? 100);
				const pending = await adapter.findPendingInvitations({
					organizationId,
				});
				if (pending.length >= invitationLimit) {
					throw APIError.from(
						"FORBIDDEN",
						ORGANIZATION_ERROR_CODES.INVITATION_LIMIT_REACHED,
					);
				}

				const teamIds =
					teamId === undefined
						? []
						: typeof teamId === "string"
							? [teamId]
							: teamId;
				if (teamIds.some((id) => id.includes(","))) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.INVALID_TEAM_ID,
					);
				}
				for (const requestedTeamId of teamIds) {
					const team = await adapter.findTeamById({
						teamId: requestedTeamId,
						organizationId,
						includeTeamMembers: true,
					});
					if (!team) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
						);
					}
					const maximumMembersPerTeam = await resolveMaximumMembersPerTeam(
						options.teams,
						{
							teamId: requestedTeamId,
							organizationId,
							session: null,
						},
					);
					if (
						maximumMembersPerTeam !== undefined &&
						team.members.length >= maximumMembersPerTeam
					) {
						throw APIError.from(
							"FORBIDDEN",
							ORGANIZATION_ERROR_CODES.TEAM_MEMBER_LIMIT_REACHED,
						);
					}
				}

				let invitationData = {
					...(data || {}),
					role: roles,
					email: normalizedEmail,
					organizationId,
					teamIds,
				};
				if (options.organizationHooks?.beforeCreateInvitation) {
					const response =
						await options.organizationHooks.beforeCreateInvitation({
							invitation: {
								...invitationData,
								inviterId: inviter.id,
								teamId: teamIds[0],
							},
							inviter: asHookUser(inviter),
							organization: asHookOrganization(organization),
						});
					if (response && typeof response === "object" && "data" in response) {
						invitationData = {
							...invitationData,
							...response.data,
						};
					}
				}
				const invitation = await adapter.createInvitation({
					invitation: invitationData,
					user: inviter,
				});
				if (options.sendInvitationEmail) {
					await options.sendInvitationEmail({
						id: invitation.id,
						role: invitation.role,
						email: invitation.email.toLowerCase(),
						organization: organization as Organization,
						inviter: {
							...(member as Member),
							user: inviter,
						},
						invitation: invitation as Invitation,
					});
				}
				if (options.organizationHooks?.afterCreateInvitation) {
					await options.organizationHooks.afterCreateInvitation({
						invitation: asHookInvitation(invitation),
						inviter: asHookUser(inviter),
						organization: asHookOrganization(organization),
					});
				}
				return { invitation };
			});
		},
		listInvitations: async ({ organizationId }) => {
			return await run(async (ctx) => {
				await requireOrganization(ctx, options, organizationId);
				const adapter = getOrgAdapter<O>(ctx, options);
				return {
					invitations: await adapter.listInvitations({ organizationId }),
				};
			});
		},
		cancelInvitation: async ({ invitationId, cancelledById }) => {
			return await run(async (ctx) => {
				const adapter = getOrgAdapter<O>(ctx, options);
				const invitation = await adapter.findInvitationById(invitationId);
				if (!invitation) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
					);
				}
				const organization = await requireOrganization(
					ctx,
					options,
					invitation.organizationId,
				);
				const cancelledBy = cancelledById
					? await requireUser(ctx, cancelledById)
					: undefined;
				if (cancelledBy && options.organizationHooks?.beforeCancelInvitation) {
					await options.organizationHooks.beforeCancelInvitation({
						invitation: asHookInvitation(invitation),
						cancelledBy: asHookUser(cancelledBy),
						organization: asHookOrganization(organization),
					});
				}
				const canceledInvitation = await adapter.updateInvitation({
					invitationId,
					status: "canceled",
					fromStatus: "pending",
				});
				if (!canceledInvitation) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
					);
				}
				if (cancelledBy && options.organizationHooks?.afterCancelInvitation) {
					await options.organizationHooks.afterCancelInvitation({
						invitation: asHookInvitation(canceledInvitation),
						cancelledBy: asHookUser(cancelledBy),
						organization: asHookOrganization(organization),
					});
				}
				return { invitation: canceledInvitation };
			});
		},
	};

	if (!options.teams?.enabled) {
		return api as OrganizationServerAPI<O>;
	}

	return {
		...api,
		createTeam: async ({
			organizationId,
			name,
			userId,
			data,
		}: CreateTeamInput) => {
			return await run(async (ctx) => {
				const adapter = getOrgAdapter<O>(ctx, options);
				const organization = await requireOrganization(
					ctx,
					options,
					organizationId,
				);
				const user = userId ? await requireUser(ctx, userId) : undefined;
				const existingTeams = await adapter.listTeams(organizationId);
				const maximum =
					typeof options.teams?.maximumTeams === "function"
						? await options.teams.maximumTeams({
								organizationId,
								session: null,
							})
						: options.teams?.maximumTeams;
				if (maximum && existingTeams.length >= maximum) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS,
					);
				}
				let teamData = {
					...(data || {}),
					name,
					organizationId,
					createdAt: new Date(),
				};
				if (options.organizationHooks?.beforeCreateTeam) {
					const response = await options.organizationHooks.beforeCreateTeam({
						team: teamData,
						...(user ? { user: asHookUser(user) } : {}),
						organization: asHookOrganization(organization),
					});
					if (response && typeof response === "object" && "data" in response) {
						teamData = {
							...teamData,
							...response.data,
						};
					}
				}
				const team = await adapter.createTeam(teamData);
				if (options.organizationHooks?.afterCreateTeam) {
					await options.organizationHooks.afterCreateTeam({
						team: asHookTeam(team),
						...(user ? { user: asHookUser(user) } : {}),
						organization: asHookOrganization(organization),
					});
				}
				return team;
			});
		},
		getTeam: async ({
			teamId,
			organizationId,
			includeMembers,
		}: GetTeamInput) => {
			return await run(async (ctx) => {
				const adapter = getOrgAdapter<O>(ctx, options);
				return await adapter.findTeamById({
					teamId,
					organizationId,
					includeTeamMembers: includeMembers,
				});
			});
		},
		updateTeam: async ({ teamId, userId, data }: UpdateTeamInput) => {
			return await run(async (ctx) => {
				const adapter = getOrgAdapter<O>(ctx, options);
				const team = await adapter.findTeamById({ teamId });
				if (!team) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
					);
				}
				const organization = await requireOrganization(
					ctx,
					options,
					team.organizationId,
				);
				const user = userId ? await requireUser(ctx, userId) : undefined;
				let updateData = { ...data };
				if (user && options.organizationHooks?.beforeUpdateTeam) {
					const response = await options.organizationHooks.beforeUpdateTeam({
						team: asHookTeam(team),
						updates: updateData,
						user: asHookUser(user),
						organization: asHookOrganization(organization),
					});
					if (response && typeof response === "object" && "data" in response) {
						updateData = {
							...updateData,
							...response.data,
						};
					}
				}
				const updatedTeam = await adapter.updateTeam(teamId, updateData);
				if (!updatedTeam) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
					);
				}
				if (user && options.organizationHooks?.afterUpdateTeam) {
					await options.organizationHooks.afterUpdateTeam({
						team: asHookTeam(updatedTeam),
						user: asHookUser(user),
						organization: asHookOrganization(organization),
					});
				}
				return updatedTeam;
			});
		},
		deleteTeam: async ({ teamId, userId }: DeleteTeamInput) => {
			return await run(async (ctx) => {
				const adapter = getOrgAdapter<O>(ctx, options);
				const team = await adapter.findTeamById({ teamId });
				if (!team) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
					);
				}
				const organization = await requireOrganization(
					ctx,
					options,
					team.organizationId,
				);
				const teams = await adapter.listTeams(team.organizationId);
				if (
					options.teams?.allowRemovingAllTeams !== true &&
					teams.length <= 1
				) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.UNABLE_TO_REMOVE_LAST_TEAM,
					);
				}
				const user = userId ? await requireUser(ctx, userId) : undefined;
				if (options.organizationHooks?.beforeDeleteTeam) {
					await options.organizationHooks.beforeDeleteTeam({
						team: asHookTeam(team),
						...(user ? { user: asHookUser(user) } : {}),
						organization: asHookOrganization(organization),
					});
				}
				await adapter.deleteTeam(teamId);
				const deletedTeam = team;
				if (options.organizationHooks?.afterDeleteTeam) {
					await options.organizationHooks.afterDeleteTeam({
						team: asHookTeam(deletedTeam),
						...(user ? { user: asHookUser(user) } : {}),
						organization: asHookOrganization(organization),
					});
				}
				return deletedTeam;
			});
		},
		listTeams: async ({ organizationId }: OrganizationIdInput) => {
			return await run(async (ctx) => {
				await requireOrganization(ctx, options, organizationId);
				const adapter = getOrgAdapter<O>(ctx, options);
				return {
					teams: await adapter.listTeams(organizationId),
				};
			});
		},
	} as OrganizationServerAPI<O>;
}
