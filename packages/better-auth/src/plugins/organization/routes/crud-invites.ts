import type { GenerateIdFn, LiteralString } from "@better-auth/core";
import { createAuthEndpoint } from "@better-auth/core/api";
import { runWithTransaction } from "@better-auth/core/context";
import { APIError } from "@better-auth/core/error";
import * as z from "zod";
import { getSessionFromCtx } from "../../../api/routes";
import { setSessionCookie } from "../../../cookies";
import type { InferAdditionalFieldsFromPluginOptions } from "../../../db";
import { toZodSchema } from "../../../db";
import { getOrgAdapter, resolveMaximumMembersPerTeam } from "../adapter";
import { orgMiddleware, orgSessionMiddleware } from "../call";
import { ORGANIZATION_ERROR_CODES } from "../error-codes";
import { hasPermission } from "../has-permission";
import { parseRoles } from "../organization";
import type { InferOrganizationRolesFromOption, Invitation } from "../schema";
import { bindOrganizationOperations } from "../server";
import type { OrganizationOptions } from "../types";

const baseInvitationSchema = z.object({
	email: z.string().meta({
		description: "The email address of the user to invite",
	}),
	role: z
		.union([
			z.string().meta({
				description: "The role to assign to the user",
			}),
			z.array(
				z.string().meta({
					description: "The roles to assign to the user",
				}),
			),
		])
		.meta({
			description:
				'The role(s) to assign to the user. It can be `admin`, `member`, owner. Eg: "member"',
		}),
	organizationId: z
		.string()
		.meta({
			description: "The organization ID to invite the user to",
		})
		.optional(),
	resend: z
		.boolean()
		.meta({
			description:
				"Resend the invitation email, if the user is already invited. Eg: true",
		})
		.optional(),
	teamId: z.union([
		z
			.string()
			.meta({
				description: "The team ID to invite the user to",
			})
			.optional(),
		z
			.array(z.string())
			.meta({
				description: "The team IDs to invite the user to",
			})
			.optional(),
	]),
});

type DynamicOrganizationRole<O extends OrganizationOptions> = O extends {
	dynamicAccessControl: { enabled: true };
}
	? LiteralString
	: never;

type OrganizationInvitationRole<O extends OrganizationOptions> =
	| InferOrganizationRolesFromOption<O>
	| DynamicOrganizationRole<O>;

type ConfiguredGenerateIdOption =
	| GenerateIdFn
	| false
	| "serial"
	| "uuid"
	| undefined;

const getAdvancedGenerateId = (
	advancedOptions: unknown,
): GenerateIdFn | undefined => {
	if (typeof advancedOptions !== "object" || advancedOptions === null) {
		return undefined;
	}
	const generateId = (advancedOptions as { generateId?: unknown }).generateId;
	if (typeof generateId !== "function") {
		return undefined;
	}
	return generateId as GenerateIdFn;
};

const hasBuiltInOpaqueInvitationIdGeneration = ({
	advancedGenerateId,
	databaseGenerateId,
}: {
	advancedGenerateId: GenerateIdFn | undefined;
	databaseGenerateId: ConfiguredGenerateIdOption;
}) =>
	advancedGenerateId === undefined &&
	(databaseGenerateId === undefined || databaseGenerateId === "uuid");

const shouldRequireVerifiedEmailForInvitationIdAction = ({
	organizationOptions,
	advancedGenerateId,
	databaseGenerateId,
}: {
	organizationOptions: OrganizationOptions;
	advancedGenerateId: GenerateIdFn | undefined;
	databaseGenerateId: ConfiguredGenerateIdOption;
}) => {
	if (organizationOptions.requireEmailVerificationOnInvitation !== undefined) {
		return organizationOptions.requireEmailVerificationOnInvitation;
	}
	return !hasBuiltInOpaqueInvitationIdGeneration({
		advancedGenerateId,
		databaseGenerateId,
	});
};

export const createInvitation = <O extends OrganizationOptions>(option: O) => {
	const additionalFieldsSchema = toZodSchema({
		fields: option?.schema?.invitation?.additionalFields || {},
		isClientSide: true,
	});

	return createAuthEndpoint(
		"/organization/invite-member",
		{
			method: "POST",
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
			body: z.object({
				...baseInvitationSchema.shape,
				...additionalFieldsSchema.shape,
			}),
			metadata: {
				$Infer: {
					body: {} as {
						/**
						 * The email address of the user
						 * to invite
						 */
						email: string;
						/**
						 * The role to assign to the user
						 */
						role:
							| OrganizationInvitationRole<O>
							| OrganizationInvitationRole<O>[];
						/**
						 * The organization ID to invite
						 * the user to
						 */
						organizationId?: string | undefined;
						/**
						 * Resend the invitation email, if
						 * the user is already invited
						 */
						resend?: boolean | undefined;
					} & (O extends { teams: { enabled: true } }
						? {
								/**
								 * The team the user is
								 * being invited to.
								 */
								teamId?: (string | string[]) | undefined;
							}
						: {}) &
						InferAdditionalFieldsFromPluginOptions<"invitation", O, false>,
				},
				openapi: {
					operationId: "createOrganizationInvitation",
					description: "Create an invitation to an organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											id: {
												type: "string",
											},
											email: {
												type: "string",
											},
											role: {
												type: "string",
											},
											organizationId: {
												type: "string",
											},
											inviterId: {
												type: "string",
											},
											status: {
												type: "string",
											},
											expiresAt: {
												type: "string",
											},
											createdAt: {
												type: "string",
											},
										},
										required: [
											"id",
											"email",
											"role",
											"organizationId",
											"inviterId",
											"status",
											"expiresAt",
											"createdAt",
										],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const session = ctx.context.session;
			const organizationId =
				ctx.body.organizationId || session.session.activeOrganizationId;
			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			const adapter = getOrgAdapter<O>(ctx.context, option as O);
			const member = await adapter.findMemberByOrgId({
				userId: session.user.id,
				organizationId: organizationId,
			});
			if (!member) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
				);
			}
			const canInvite = await hasPermission(
				{
					role: member.role,
					options: ctx.context.orgOptions,
					permissions: {
						invitation: ["create"],
					},
					organizationId,
				},
				ctx,
			);

			if (!canInvite) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION,
				);
			}

			const creatorRole = ctx.context.orgOptions.creatorRole || "owner";

			const roles = parseRoles(ctx.body.role);

			if (
				!member.role
					.split(",")
					.map((r) => r.trim())
					.includes(creatorRole) &&
				roles.split(",").includes(creatorRole)
			) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE,
				);
			}

			const body = ctx.body as typeof ctx.body & {
				teamId?: string | string[] | undefined;
			};
			const {
				email: inputEmail,
				role: inputRole,
				organizationId: _,
				resend,
				teamId,
				...additionalFields
			} = body;
			const { invitation } = await bindOrganizationOperations(
				option,
				ctx.context,
				{ session, endpointContext: ctx },
			).createInvitation({
				organizationId,
				email: inputEmail,
				role: inputRole,
				inviterId: session.user.id,
				teamId,
				resend,
				data: additionalFields,
			});
			return ctx.json(invitation);
		},
	);
};

const acceptInvitationBodySchema = z.object({
	invitationId: z.string().meta({
		description: "The ID of the invitation to accept",
	}),
});

export const acceptInvitation = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/accept-invitation",
		{
			method: "POST",
			body: acceptInvitationBodySchema,
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
			metadata: {
				openapi: {
					description: "Accept an invitation to an organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											invitation: {
												type: "object",
											},
											member: {
												type: "object",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const session = ctx.context.session;
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const invitation = await adapter.findInvitationById(
				ctx.body.invitationId,
			);

			if (
				!invitation ||
				invitation.expiresAt < new Date() ||
				invitation.status !== "pending"
			) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
				);
			}

			// TODO(#9124): `session.user.email` becomes nullable in v2 — this
			// comparison and its mirrors in rejectInvitation, getInvitation, and
			// listUserInvitations need null handling.
			if (invitation.email.toLowerCase() !== session.user.email.toLowerCase()) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION,
				);
			}

			if (
				shouldRequireVerifiedEmailForInvitationIdAction({
					organizationOptions: ctx.context.orgOptions,
					advancedGenerateId: getAdvancedGenerateId(
						ctx.context.options.advanced,
					),
					databaseGenerateId:
						ctx.context.options.advanced?.database?.generateId,
				}) &&
				!session.user.emailVerified
			) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION,
				);
			}

			const membershipLimit = ctx.context.orgOptions?.membershipLimit || 100;
			const membersCount = await adapter.countMembers({
				organizationId: invitation.organizationId,
			});

			const organization = await adapter.findOrganizationById(
				invitation.organizationId,
			);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			const limit =
				typeof membershipLimit === "number"
					? membershipLimit
					: await membershipLimit(session.user, organization);

			if (membersCount >= limit) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_MEMBERSHIP_LIMIT_REACHED,
				);
			}

			// Run beforeAcceptInvitation hook
			if (options?.organizationHooks?.beforeAcceptInvitation) {
				await options?.organizationHooks.beforeAcceptInvitation({
					invitation: invitation as unknown as Invitation,
					user: session.user,
					organization,
				});
			}

			// Claim the invitation atomically so only one concurrent accept wins the
			// pending -> accepted transition; the guarded update is a single statement
			// and atomic on every adapter. The membership work then runs in a
			// transaction so it is all-or-nothing where the adapter supports it, and if
			// it fails the claim is released back to pending so the invitee can retry
			// instead of being stranded as accepted with no membership.
			const acceptedI = await adapter.updateInvitation({
				invitationId: ctx.body.invitationId,
				status: "accepted",
				fromStatus: "pending",
			});
			if (!acceptedI) {
				// Another request already accepted this invitation.
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
				);
			}

			const member = await runWithTransaction(ctx.context.adapter, async () => {
				if (
					ctx.context.orgOptions.teams &&
					ctx.context.orgOptions.teams.enabled &&
					"teamId" in acceptedI &&
					acceptedI.teamId
				) {
					const teamIds = (acceptedI.teamId as string).split(",");
					const onlyOne = teamIds.length === 1;

					for (const teamId of teamIds) {
						// Confirm the team still belongs to the accepted invitation's
						// organization before adding the member. This keeps team
						// membership consistent with the invitation's organization,
						// including for older invitations and for teams that were
						// moved or removed between invite and accept.
						const team = await adapter.findTeamById({
							teamId,
							organizationId: acceptedI.organizationId,
						});
						if (!team) {
							throw APIError.from(
								"BAD_REQUEST",
								ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
							);
						}

						const maximumMembersPerTeam = await resolveMaximumMembersPerTeam(
							ctx.context.orgOptions.teams,
							{
								teamId,
								organizationId: acceptedI.organizationId,
								session,
							},
						);
						if (maximumMembersPerTeam !== undefined) {
							const result = await adapter.addTeamMemberWithLimit({
								teamId,
								userId: session.user.id,
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
								teamId: teamId,
								userId: session.user.id,
							});
						}
					}

					if (onlyOne) {
						const teamId = teamIds[0]!;
						const updatedSession = await adapter.setActiveTeam(
							session.session.token,
							teamId,
							ctx,
						);

						await setSessionCookie(ctx, {
							session: updatedSession,
							user: session.user,
						});
					}
				}

				const createdMember = await adapter.createMember({
					organizationId: acceptedI.organizationId,
					userId: session.user.id,
					role: acceptedI.role,
					createdAt: new Date(),
				});

				await adapter.setActiveOrganization(
					session.session.token,
					acceptedI.organizationId,
					ctx,
				);

				return createdMember;
			}).catch(async (error) => {
				// The membership work failed; release the claim so the invitation is
				// pending again and the invitee can retry.
				await adapter.updateInvitation({
					invitationId: ctx.body.invitationId,
					status: "pending",
				});
				throw error;
			});

			if (options?.organizationHooks?.afterAcceptInvitation) {
				await options?.organizationHooks.afterAcceptInvitation({
					invitation: acceptedI as unknown as Invitation,
					member,
					user: session.user,
					organization,
				});
			}
			return ctx.json({
				invitation: acceptedI,
				member,
			});
		},
	);

const rejectInvitationBodySchema = z.object({
	invitationId: z.string().meta({
		description: "The ID of the invitation to reject",
	}),
});

export const rejectInvitation = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/reject-invitation",
		{
			method: "POST",
			body: rejectInvitationBodySchema,
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
			metadata: {
				openapi: {
					description: "Reject an invitation to an organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											invitation: {
												type: "object",
											},
											member: {
												type: "object",
												nullable: true,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const session = ctx.context.session;
			const adapter = getOrgAdapter(ctx.context, ctx.context.orgOptions);
			const invitation = await adapter.findInvitationById(
				ctx.body.invitationId,
			);
			if (!invitation || invitation.status !== "pending") {
				throw APIError.from("BAD_REQUEST", {
					message: "Invitation not found!",
					code: "INVITATION_NOT_FOUND",
				});
			}
			if (invitation.email.toLowerCase() !== session.user.email.toLowerCase()) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION,
				);
			}

			if (
				shouldRequireVerifiedEmailForInvitationIdAction({
					organizationOptions: ctx.context.orgOptions,
					advancedGenerateId: getAdvancedGenerateId(
						ctx.context.options.advanced,
					),
					databaseGenerateId:
						ctx.context.options.advanced?.database?.generateId,
				}) &&
				!session.user.emailVerified
			) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION,
				);
			}

			const organization = await adapter.findOrganizationById(
				invitation.organizationId,
			);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			// Run beforeRejectInvitation hook
			if (options?.organizationHooks?.beforeRejectInvitation) {
				await options?.organizationHooks.beforeRejectInvitation({
					invitation: invitation as unknown as Invitation,
					user: session.user,
					organization,
				});
			}

			const rejectedI = await adapter.updateInvitation({
				invitationId: ctx.body.invitationId,
				status: "rejected",
			});

			// Run afterRejectInvitation hook
			if (options?.organizationHooks?.afterRejectInvitation) {
				await options?.organizationHooks.afterRejectInvitation({
					invitation: rejectedI || (invitation as unknown as Invitation),
					user: session.user,
					organization,
				});
			}

			return ctx.json({
				invitation: rejectedI,
				member: null,
			});
		},
	);

const cancelInvitationBodySchema = z.object({
	invitationId: z.string().meta({
		description: "The ID of the invitation to cancel",
	}),
});

export const cancelInvitation = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/cancel-invitation",
		{
			method: "POST",
			body: cancelInvitationBodySchema,
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
			openapi: {
				operationId: "cancelOrganizationInvitation",
				description: "Cancel an invitation to an organization",
				responses: {
					"200": {
						description: "Success",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										invitation: {
											type: "object",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const session = ctx.context.session;
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const invitation = await adapter.findInvitationById(
				ctx.body.invitationId,
			);
			if (!invitation) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
				);
			}
			const member = await adapter.findMemberByOrgId({
				userId: session.user.id,
				organizationId: invitation.organizationId,
			});
			if (!member) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
				);
			}
			const canCancel = await hasPermission(
				{
					role: member.role,
					options: ctx.context.orgOptions,
					permissions: {
						invitation: ["cancel"],
					},
					organizationId: invitation.organizationId,
				},
				ctx,
			);

			if (!canCancel) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION,
				);
			}

			const { invitation: canceledInvitation } =
				await bindOrganizationOperations(options, ctx.context, {
					session,
					endpointContext: ctx,
				}).cancelInvitation({
					invitationId: ctx.body.invitationId,
					cancelledById: session.user.id,
				});

			return ctx.json(canceledInvitation);
		},
	);

const getInvitationQuerySchema = z.object({
	id: z.string().meta({
		description: "The ID of the invitation to get",
	}),
});

export const getInvitation = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/get-invitation",
		{
			method: "GET",
			use: [orgMiddleware],
			requireHeaders: true,
			query: getInvitationQuerySchema,
			metadata: {
				openapi: {
					description: "Get an invitation by ID",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											id: {
												type: "string",
											},
											email: {
												type: "string",
											},
											role: {
												type: "string",
											},
											organizationId: {
												type: "string",
											},
											inviterId: {
												type: "string",
											},
											status: {
												type: "string",
											},
											expiresAt: {
												type: "string",
											},
											organizationName: {
												type: "string",
											},
											organizationSlug: {
												type: "string",
											},
											inviterEmail: {
												type: "string",
											},
										},
										required: [
											"id",
											"email",
											"role",
											"organizationId",
											"inviterId",
											"status",
											"expiresAt",
											"organizationName",
											"organizationSlug",
											"inviterEmail",
										],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const session = await getSessionFromCtx(ctx);
			if (!session) {
				throw APIError.fromStatus("UNAUTHORIZED", {
					message: "Not authenticated",
				});
			}
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const invitation = await adapter.findInvitationById(ctx.query.id);
			if (
				!invitation ||
				invitation.status !== "pending" ||
				invitation.expiresAt < new Date()
			) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "Invitation not found!",
				});
			}
			if (invitation.email.toLowerCase() !== session.user.email.toLowerCase()) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION,
				);
			}
			if (
				shouldRequireVerifiedEmailForInvitationIdAction({
					organizationOptions: ctx.context.orgOptions,
					advancedGenerateId: getAdvancedGenerateId(
						ctx.context.options.advanced,
					),
					databaseGenerateId:
						ctx.context.options.advanced?.database?.generateId,
				}) &&
				!session.user.emailVerified
			) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION,
				);
			}
			const organization = await adapter.findOrganizationById(
				invitation.organizationId,
			);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}
			const member = await adapter.findMemberByOrgId({
				userId: invitation.inviterId,
				organizationId: invitation.organizationId,
			});
			if (!member) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION,
				);
			}

			return ctx.json({
				...invitation,
				organizationName: organization.name,
				organizationSlug: organization.slug,
				inviterEmail: member.user.email,
			});
		},
	);

const listInvitationQuerySchema = z
	.object({
		organizationId: z
			.string()
			.meta({
				description: "The ID of the organization to list invitations for",
			})
			.optional(),
	})
	.optional();

export const listInvitations = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/list-invitations",
		{
			method: "GET",
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
			query: listInvitationQuerySchema,
		},
		async (ctx) => {
			const session = await getSessionFromCtx(ctx);
			if (!session) {
				throw APIError.fromStatus("UNAUTHORIZED", {
					message: "Not authenticated",
				});
			}
			const orgId =
				ctx.query?.organizationId || session.session.activeOrganizationId;
			if (!orgId) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "Organization ID is required",
				});
			}
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const isMember = await adapter.findMemberByOrgId({
				userId: session.user.id,
				organizationId: orgId,
			});
			if (!isMember) {
				throw APIError.fromStatus("FORBIDDEN", {
					message: "You are not a member of this organization",
				});
			}
			const { invitations } = await bindOrganizationOperations(
				options,
				ctx.context,
				{ session, endpointContext: ctx },
			).listInvitations({ organizationId: orgId });
			return ctx.json(invitations);
		},
	);

/**
 * List all invitations a user has received
 */
export const listUserInvitations = <O extends OrganizationOptions>(
	options: O,
) =>
	createAuthEndpoint(
		"/organization/list-user-invitations",
		{
			method: "GET",
			use: [orgMiddleware],
			query: z
				.object({
					email: z
						.string()
						.meta({
							description:
								"The email of the user to list invitations for. This only works for server side API calls.",
						})
						.optional(),
				})
				.optional(),
			metadata: {
				openapi: {
					description: "List all invitations a user has received",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "array",
										items: {
											type: "object",
											properties: {
												id: {
													type: "string",
												},
												email: {
													type: "string",
												},
												role: {
													type: "string",
												},
												organizationId: {
													type: "string",
												},
												organizationName: {
													type: "string",
												},
												inviterId: {
													type: "string",
													description:
														"The ID of the user who created the invitation",
												},
												teamId: {
													type: "string",
													description:
														"The ID of the team associated with the invitation",
													nullable: true,
												},
												status: {
													type: "string",
												},
												expiresAt: {
													type: "string",
												},
												createdAt: {
													type: "string",
												},
											},
											required: [
												"id",
												"email",
												"role",
												"organizationId",
												"organizationName",
												"inviterId",
												"status",
												"expiresAt",
												"createdAt",
											],
										},
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const session = await getSessionFromCtx(ctx);

			if (ctx.request && ctx.query?.email) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "User email cannot be passed for client side API calls.",
				});
			}

			// When the caller has a session, require an ownership signal stronger
			// than the email string before enumerating invitations targeted at it.
			// Server-side SDK calls without a session are trusted and skip the gate.
			if (session && !session.user.emailVerified) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION,
				);
			}

			const userEmail = session?.user.email || ctx.query?.email;
			if (!userEmail) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "Missing session headers, or email query parameter.",
				});
			}
			const adapter = getOrgAdapter<O>(ctx.context, options);

			const invitations = await adapter.listUserInvitations(userEmail);
			const pendingInvitations = invitations.filter(
				(inv) => inv.status === "pending",
			);
			return ctx.json(pendingInvitations);
		},
	);
