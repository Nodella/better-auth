import type { AuthContext, BetterAuthOptions } from "@better-auth/core";
import type { Session, User } from "@better-auth/core/db";
import type { Where, WhereOperator } from "@better-auth/core/db/adapter";
import { APIError, BASE_ERROR_CODES } from "@better-auth/core/error";
import * as z from "zod";
import { parseSessionOutput, parseUserOutput } from "../../db/schema";
import { getDate } from "../../utils/date";
import { ADMIN_ERROR_CODES } from "./error-codes";
import type {
	AdminOptions,
	InferAdminRolesFromOption,
	SessionWithImpersonatedBy,
	UserWithRole,
} from "./types";

type ServerRun = <Result>(
	fn: (ctx: AuthContext) => Result | Promise<Result>,
) => Promise<Result>;

type ServerStatus = {
	status: true;
};

type ServerSuccess = {
	success: true;
};

type AdminServerRole<O extends AdminOptions> =
	| InferAdminRolesFromOption<O>
	| InferAdminRolesFromOption<O>[];

type CreateUserInput<O extends AdminOptions> = {
	email: string;
	name: string;
	password?: string | undefined;
	role?: AdminServerRole<O> | undefined;
	data?: Record<string, unknown> | undefined;
};

type UpdateUserInput = {
	userId: string;
	data: Record<string, unknown>;
};

type SetRoleInput<O extends AdminOptions> = {
	userId: string;
	role: AdminServerRole<O>;
};

type ListUsersInput = {
	searchValue?: string | undefined;
	searchField?: "email" | "name" | undefined;
	searchOperator?:
		| Extract<WhereOperator, "contains" | "starts_with" | "ends_with">
		| undefined;
	limit?: string | number | undefined;
	offset?: string | number | undefined;
	sortBy?: string | undefined;
	sortDirection?: "asc" | "desc" | undefined;
	filterField?: string | undefined;
	filterValue?: string | number | boolean | string[] | number[] | undefined;
	filterOperator?: WhereOperator | undefined;
};

type UserIdInput = {
	userId: string;
};

type BanUserInput = UserIdInput & {
	banReason?: string | undefined;
	banExpiresIn?: number | undefined;
};

type RevokeUserSessionInput = {
	sessionToken: string;
};

type SetUserPasswordInput = UserIdInput & {
	newPassword: string;
};

type ServerUser<Options extends BetterAuthOptions> = User<
	Options["user"],
	Options["plugins"]
> &
	UserWithRole;

type ServerSession<Options extends BetterAuthOptions> = Session<
	Options["session"],
	Options["plugins"]
> &
	SessionWithImpersonatedBy;

function parseRoles(roles: string | string[]): string {
	return Array.isArray(roles) ? roles.join(",") : roles;
}

function validateRoleInput<O extends AdminOptions>(
	opts: O,
	role: unknown,
): string | string[] {
	const inputRoles = Array.isArray(role) ? role : [role];
	for (const inputRole of inputRoles) {
		if (typeof inputRole !== "string") {
			throw APIError.from("BAD_REQUEST", ADMIN_ERROR_CODES.INVALID_ROLE_TYPE);
		}
		if (opts.roles && !opts.roles[inputRole as keyof typeof opts.roles]) {
			throw APIError.from(
				"BAD_REQUEST",
				ADMIN_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE,
			);
		}
	}
	return Array.isArray(role) ? inputRoles : inputRoles[0]!;
}

async function requireUser(ctx: AuthContext, userId: string) {
	const user = await ctx.internalAdapter.findUserById(userId);
	if (!user) {
		throw APIError.from("NOT_FOUND", BASE_ERROR_CODES.USER_NOT_FOUND);
	}
	return user;
}

async function validatePassword(ctx: AuthContext, password: string) {
	const minPasswordLength = ctx.password.config.minPasswordLength;
	if (password.length < minPasswordLength) {
		ctx.logger.warn("Password is too short");
		throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.PASSWORD_TOO_SHORT);
	}
	const maxPasswordLength = ctx.password.config.maxPasswordLength;
	if (password.length > maxPasswordLength) {
		ctx.logger.warn("Password is too long");
		throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.PASSWORD_TOO_LONG);
	}
}

async function setCredentialPassword(
	ctx: AuthContext,
	userId: string,
	password: string,
) {
	await validatePassword(ctx, password);
	await requireUser(ctx, userId);
	const hashedPassword = await ctx.password.hash(password);
	const accounts = await ctx.internalAdapter.findAccounts(userId);
	const credentialAccount = accounts.find(
		(account) => account.providerId === "credential",
	);
	if (credentialAccount) {
		await ctx.internalAdapter.updatePassword(userId, hashedPassword);
		return;
	}
	await ctx.internalAdapter.createAccount({
		userId,
		providerId: "credential",
		accountId: userId,
		password: hashedPassword,
	});
}

export type AdminServerAPI<
	O extends AdminOptions,
	Options extends BetterAuthOptions = BetterAuthOptions,
> = {
	getUser: (input: UserIdInput) => Promise<ServerUser<Options>>;
	createUser: (
		input: CreateUserInput<O>,
	) => Promise<{ user: ServerUser<Options> }>;
	listUsers: (input?: ListUsersInput | undefined) => Promise<{
		users: ServerUser<Options>[];
		total: number;
		limit?: number | undefined;
		offset?: number | undefined;
	}>;
	updateUser: (input: UpdateUserInput) => Promise<ServerUser<Options>>;
	setRole: (input: SetRoleInput<O>) => Promise<{ user: ServerUser<Options> }>;
	banUser: (input: BanUserInput) => Promise<{ user: ServerUser<Options> }>;
	unbanUser: (input: UserIdInput) => Promise<{ user: ServerUser<Options> }>;
	listUserSessions: (
		input: UserIdInput,
	) => Promise<{ sessions: ServerSession<Options>[] }>;
	revokeUserSession: (input: RevokeUserSessionInput) => Promise<ServerSuccess>;
	revokeUserSessions: (input: UserIdInput) => Promise<ServerSuccess>;
	removeUser: (input: UserIdInput) => Promise<ServerSuccess>;
	setUserPassword: (input: SetUserPasswordInput) => Promise<ServerStatus>;
};

export function createAdminServerAPI<
	O extends AdminOptions,
	Options extends BetterAuthOptions = BetterAuthOptions,
>(opts: O, run: ServerRun): AdminServerAPI<O, Options> {
	return {
		getUser: async ({ userId }) => {
			return await run(async (ctx) => {
				const user = await requireUser(ctx, userId);
				return parseUserOutput(ctx.options, user) as ServerUser<Options>;
			});
		},
		createUser: async ({ email, name, password, role, data }) => {
			return await run(async (ctx) => {
				const { role: dataRole, ...userData } = data ?? {};
				const requestedRole = role ?? dataRole;
				let parsedRole: string | undefined;
				if (requestedRole !== undefined) {
					parsedRole = parseRoles(validateRoleInput(opts, requestedRole));
				}

				const normalizedEmail = email.toLowerCase();
				if (!z.email().safeParse(normalizedEmail).success) {
					throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_EMAIL);
				}
				const existingUser =
					await ctx.internalAdapter.findUserByEmail(normalizedEmail);
				if (existingUser) {
					throw APIError.from(
						"BAD_REQUEST",
						ADMIN_ERROR_CODES.USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
					);
				}

				const user = await ctx.internalAdapter.createUser<UserWithRole>({
					...userData,
					email: normalizedEmail,
					name,
					role: parsedRole ?? opts.defaultRole ?? "user",
				});
				if (!user) {
					throw APIError.from(
						"INTERNAL_SERVER_ERROR",
						ADMIN_ERROR_CODES.FAILED_TO_CREATE_USER,
					);
				}
				if (password) {
					await setCredentialPassword(ctx, user.id, password);
				}
				return {
					user: parseUserOutput(ctx.options, user) as ServerUser<Options>,
				};
			});
		},
		listUsers: async (input) => {
			return await run(async (ctx) => {
				const where: Where[] = [];
				if (input?.searchValue) {
					where.push({
						field: input.searchField || "email",
						operator: input.searchOperator || "contains",
						value: input.searchValue,
					});
				}
				if (input?.filterValue !== undefined) {
					where.push({
						field: input.filterField || "email",
						operator: input.filterOperator || "eq",
						value: input.filterValue,
					});
				}

				const limit = Number(input?.limit) || undefined;
				const offset = Number(input?.offset) || undefined;
				const users = await ctx.internalAdapter.listUsers(
					limit,
					offset,
					input?.sortBy
						? {
								field: input.sortBy,
								direction: input.sortDirection || "asc",
							}
						: undefined,
					where.length ? where : undefined,
				);
				const total = await ctx.internalAdapter.countTotalUsers(
					where.length ? where : undefined,
				);
				return {
					users: users.map((user) =>
						parseUserOutput(ctx.options, user),
					) as ServerUser<Options>[],
					total,
					limit,
					offset,
				};
			});
		},
		updateUser: async ({ userId, data }) => {
			return await run(async (ctx) => {
				if (Object.keys(data).length === 0) {
					throw APIError.from(
						"BAD_REQUEST",
						ADMIN_ERROR_CODES.NO_DATA_TO_UPDATE,
					);
				}
				if (Object.prototype.hasOwnProperty.call(data, "password")) {
					throw APIError.from(
						"BAD_REQUEST",
						ADMIN_ERROR_CODES.PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER,
					);
				}

				const updateData = { ...data };
				if (Object.prototype.hasOwnProperty.call(updateData, "role")) {
					updateData.role = parseRoles(
						validateRoleInput(opts, updateData.role),
					);
				}
				if (Object.prototype.hasOwnProperty.call(updateData, "email")) {
					const email = String(updateData.email).toLowerCase();
					if (!z.email().safeParse(email).success) {
						throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_EMAIL);
					}
					const existingUser = await ctx.internalAdapter.findUserByEmail(email);
					if (existingUser && existingUser.user.id !== userId) {
						throw APIError.from(
							"BAD_REQUEST",
							ADMIN_ERROR_CODES.USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
						);
					}
					updateData.email = email;
				}

				await requireUser(ctx, userId);
				const updatedUser = await ctx.internalAdapter.updateUser(
					userId,
					updateData,
				);
				if (updateData.banned === true) {
					await ctx.internalAdapter.deleteUserSessions(userId);
				}
				return parseUserOutput(ctx.options, updatedUser) as ServerUser<Options>;
			});
		},
		setRole: async ({ userId, role }) => {
			return await run(async (ctx) => {
				await requireUser(ctx, userId);
				const updatedUser = await ctx.internalAdapter.updateUser(userId, {
					role: parseRoles(validateRoleInput(opts, role)),
				});
				return {
					user: parseUserOutput(
						ctx.options,
						updatedUser,
					) as ServerUser<Options>,
				};
			});
		},
		banUser: async ({ userId, banReason, banExpiresIn }) => {
			return await run(async (ctx) => {
				await requireUser(ctx, userId);
				const user = await ctx.internalAdapter.updateUser(userId, {
					banned: true,
					banReason: banReason || opts.defaultBanReason || "No reason",
					banExpires: banExpiresIn
						? getDate(banExpiresIn, "sec")
						: opts.defaultBanExpiresIn
							? getDate(opts.defaultBanExpiresIn, "sec")
							: undefined,
					updatedAt: new Date(),
				});
				await ctx.internalAdapter.deleteUserSessions(userId);
				return {
					user: parseUserOutput(ctx.options, user) as ServerUser<Options>,
				};
			});
		},
		unbanUser: async ({ userId }) => {
			return await run(async (ctx) => {
				await requireUser(ctx, userId);
				const user = await ctx.internalAdapter.updateUser(userId, {
					banned: false,
					banExpires: null,
					banReason: null,
					updatedAt: new Date(),
				});
				return {
					user: parseUserOutput(ctx.options, user) as ServerUser<Options>,
				};
			});
		},
		listUserSessions: async ({ userId }) => {
			return await run(async (ctx) => {
				const sessions = await ctx.internalAdapter.listSessions(userId);
				return {
					sessions: sessions.map((session) =>
						parseSessionOutput(ctx.options, session),
					) as ServerSession<Options>[],
				};
			});
		},
		revokeUserSession: async ({ sessionToken }) => {
			return await run(async (ctx) => {
				await ctx.internalAdapter.deleteSession(sessionToken);
				return { success: true };
			});
		},
		revokeUserSessions: async ({ userId }) => {
			return await run(async (ctx) => {
				await ctx.internalAdapter.deleteUserSessions(userId);
				return { success: true };
			});
		},
		removeUser: async ({ userId }) => {
			return await run(async (ctx) => {
				await requireUser(ctx, userId);
				await ctx.internalAdapter.deleteUserSessions(userId);
				await ctx.internalAdapter.deleteUser(userId);
				return { success: true };
			});
		},
		setUserPassword: async ({ userId, newPassword }) => {
			return await run(async (ctx) => {
				await setCredentialPassword(ctx, userId, newPassword);
				return { status: true };
			});
		},
	};
}
