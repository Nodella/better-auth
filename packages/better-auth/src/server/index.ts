import type {
	AuthContext,
	BetterAuthOptions,
	BetterAuthPlugin,
} from "@better-auth/core";
import { runWithAdapter } from "@better-auth/core/context";
import type { Account, Session, User } from "@better-auth/core/db";
import { APIError, BASE_ERROR_CODES } from "@better-auth/core/error";
import {
	parseAccountOutput,
	parseSessionOutput,
	parseUserInput,
	parseUserOutput,
} from "../db/schema";
import type { AdditionalUserFieldsInput } from "../types";

type SafeServerAccount<Options extends BetterAuthOptions> = Omit<
	Account<Options["account"], Options["plugins"]>,
	| "accessToken"
	| "refreshToken"
	| "idToken"
	| "accessTokenExpiresAt"
	| "refreshTokenExpiresAt"
	| "password"
	| "scope"
> & {
	scopes: string[];
};

type ServerStatus = {
	status: true;
};

type ServerUpdateUserInput<Options extends BetterAuthOptions> = Partial<
	AdditionalUserFieldsInput<Options>
> & {
	name?: string | undefined;
	image?: string | null | undefined;
};

type ServerListSessionsOptions = {
	/**
	 * Whether to return only active sessions.
	 *
	 * @default true
	 */
	onlyActive?: boolean | undefined;
};

type ServerSetPasswordOptions = {
	/**
	 * Revoke all existing sessions for this user after changing the password.
	 *
	 * @default false
	 */
	revokeSessions?: boolean | undefined;
};

type ServerCreateSessionOptions = {
	/**
	 * Create a session that follows the "don't remember me" expiration policy.
	 */
	dontRememberMe?: boolean | undefined;
};

export type BetterAuthServerUserAPI<Options extends BetterAuthOptions> = {
	/**
	 * Return the user identified by this trusted server-side user scope.
	 */
	get: () => Promise<User<Options["user"], Options["plugins"]> | null>;
	/**
	 * Update this user from trusted server-side code.
	 */
	update: (
		data: ServerUpdateUserInput<Options>,
	) => Promise<User<Options["user"], Options["plugins"]>>;
	/**
	 * Delete this user and their sessions from trusted server-side code.
	 */
	delete: () => Promise<ServerStatus>;
	/**
	 * List accounts linked to this user without requiring request headers.
	 */
	listAccounts: () => Promise<SafeServerAccount<Options>[]>;
	/**
	 * List this user's sessions without requiring request headers.
	 */
	listSessions: (
		options?: ServerListSessionsOptions | undefined,
	) => Promise<Session<Options["session"], Options["plugins"]>[]>;
	/**
	 * Revoke a single session token if it belongs to this user.
	 */
	revokeSession: (token: string) => Promise<ServerStatus>;
	/**
	 * Revoke every session belonging to this user.
	 */
	revokeSessions: () => Promise<ServerStatus>;
	/**
	 * Set or replace this user's credential password.
	 */
	setPassword: (
		newPassword: string,
		options?: ServerSetPasswordOptions | undefined,
	) => Promise<ServerStatus>;
	/**
	 * Create a new session for this user and return its token-bearing session
	 * record. No cookies are written in headless/server mode.
	 */
	createSession: (
		options?: ServerCreateSessionOptions | undefined,
	) => Promise<Session<Options["session"], Options["plugins"]>>;
};

export type BetterAuthServerSessionAPI<Options extends BetterAuthOptions> = {
	/**
	 * Resolve an explicit session token without using request headers.
	 */
	get: () => Promise<{
		session: Session<Options["session"], Options["plugins"]>;
		user: User<Options["user"], Options["plugins"]>;
	} | null>;
	/**
	 * Revoke this explicit session token.
	 */
	revoke: () => Promise<ServerStatus>;
};

type InferPluginServerAPI<Options extends BetterAuthOptions> =
	Options["plugins"] extends readonly [unknown, ...unknown[]]
		? InferPluginServerAPIFromTuple<Options["plugins"]>
		: Options["plugins"] extends Array<infer Plugin>
			? Plugin extends {
					server: (...args: infer _Args) => infer ServerAPI;
				}
				? ServerAPI extends Record<string, unknown>
					? ServerAPI
					: {}
				: {}
			: {};

type InferPluginServerAPIFromTuple<
	Plugins extends readonly unknown[],
	Acc = {},
> = Plugins extends readonly [infer Head, ...infer Tail]
	? InferPluginServerAPIFromTuple<
			Tail,
			Acc &
				(Head extends {
					server: (...args: infer _Args) => infer ServerAPI;
				}
					? ServerAPI extends Record<string, unknown>
						? ServerAPI
						: {}
					: {})
		>
	: Acc;

export type BetterAuthServerCoreAPI<Options extends BetterAuthOptions> = {
	/**
	 * Create a trusted server-side user scope.
	 */
	user: (userId: string) => BetterAuthServerUserAPI<Options>;
	/**
	 * Alias for `user(userId)` that reads naturally in server-only code.
	 */
	getUser: (userId: string) => BetterAuthServerUserAPI<Options>;
	/**
	 * Create a trusted server-side session-token scope.
	 */
	session: (token: string) => BetterAuthServerSessionAPI<Options>;
};

export type BetterAuthServerAPI<Options extends BetterAuthOptions> =
	BetterAuthServerCoreAPI<Options> & InferPluginServerAPI<Options>;

export function createBetterAuthServerAPI<Options extends BetterAuthOptions>(
	ctxPromise: Promise<AuthContext<Options>>,
	plugins: BetterAuthPlugin[] = [],
): BetterAuthServerAPI<Options> {
	const run = async <Result>(
		fn: (ctx: AuthContext<Options>) => Result | Promise<Result>,
	) => {
		const ctx = await ctxPromise;
		return await runWithAdapter(ctx.adapter, () => fn(ctx));
	};

	const requireUser = async (ctx: AuthContext<Options>, userId: string) => {
		const user = await ctx.internalAdapter.findUserById(userId);
		if (!user) {
			throw APIError.from("NOT_FOUND", BASE_ERROR_CODES.USER_NOT_FOUND);
		}
		return user;
	};

	const createUserScope = (
		userId: string,
	): BetterAuthServerUserAPI<Options> => ({
		get: async () => {
			return run(async (ctx) => {
				const user = await ctx.internalAdapter.findUserById(userId);
				if (!user) return null;
				return parseUserOutput(ctx.options, user) as User<
					Options["user"],
					Options["plugins"]
				>;
			});
		},
		update: async (data) => {
			return run(async (ctx) => {
				await requireUser(ctx, userId);
				if (data === null || typeof data !== "object" || Array.isArray(data)) {
					throw APIError.from(
						"BAD_REQUEST",
						BASE_ERROR_CODES.BODY_MUST_BE_AN_OBJECT,
					);
				}
				if ("email" in data) {
					throw APIError.from(
						"BAD_REQUEST",
						BASE_ERROR_CODES.EMAIL_CAN_NOT_BE_UPDATED,
					);
				}

				const { name, image, ...rest } = data;
				const additionalFields = parseUserInput(ctx.options, rest, "update");
				if (
					name === undefined &&
					image === undefined &&
					Object.keys(additionalFields).length === 0
				) {
					throw APIError.fromStatus("BAD_REQUEST", {
						message: "No fields to update",
					});
				}

				const user = await ctx.internalAdapter.updateUser(userId, {
					...(name !== undefined ? { name } : {}),
					...(image !== undefined ? { image } : {}),
					...additionalFields,
				});
				return parseUserOutput(ctx.options, user) as User<
					Options["user"],
					Options["plugins"]
				>;
			});
		},
		delete: async () => {
			return run(async (ctx) => {
				const user = await ctx.internalAdapter.findUserById(userId);
				if (!user) {
					return { status: true };
				}

				const beforeDelete = ctx.options.user?.deleteUser?.beforeDelete;
				if (beforeDelete) {
					await beforeDelete(user, undefined);
				}
				await ctx.internalAdapter.deleteUser(userId);
				await ctx.internalAdapter.deleteUserSessions(userId);
				const afterDelete = ctx.options.user?.deleteUser?.afterDelete;
				if (afterDelete) {
					await afterDelete(user, undefined);
				}
				return { status: true };
			});
		},
		listAccounts: async () => {
			return run(async (ctx) => {
				const accounts = await ctx.internalAdapter.findAccounts(userId);
				return accounts.map((account) => {
					const { scope, ...parsed } = parseAccountOutput(ctx.options, account);
					return {
						...parsed,
						scopes: scope?.split(",") || [],
					} as SafeServerAccount<Options>;
				});
			});
		},
		listSessions: async (options) => {
			return run(async (ctx) => {
				const onlyActive = options?.onlyActive ?? true;
				const sessions = await ctx.internalAdapter.listSessions(userId, {
					onlyActiveSessions: onlyActive,
				});
				const filteredSessions = onlyActive
					? sessions.filter((session) => session.expiresAt > new Date())
					: sessions;
				return filteredSessions.map((session) =>
					parseSessionOutput(ctx.options, session),
				) as Session<Options["session"], Options["plugins"]>[];
			});
		},
		revokeSession: async (token) => {
			return run(async (ctx) => {
				const session = await ctx.internalAdapter.findSession(token);
				if (session?.session.userId === userId) {
					await ctx.internalAdapter.deleteSession(token);
				}
				return { status: true };
			});
		},
		revokeSessions: async () => {
			return run(async (ctx) => {
				await ctx.internalAdapter.deleteUserSessions(userId);
				return { status: true };
			});
		},
		setPassword: async (newPassword, options) => {
			return run(async (ctx) => {
				await requireUser(ctx, userId);
				const minPasswordLength = ctx.password.config.minPasswordLength;
				if (newPassword.length < minPasswordLength) {
					ctx.logger.warn("Password is too short");
					throw APIError.from(
						"BAD_REQUEST",
						BASE_ERROR_CODES.PASSWORD_TOO_SHORT,
					);
				}

				const maxPasswordLength = ctx.password.config.maxPasswordLength;
				if (newPassword.length > maxPasswordLength) {
					ctx.logger.warn("Password is too long");
					throw APIError.from(
						"BAD_REQUEST",
						BASE_ERROR_CODES.PASSWORD_TOO_LONG,
					);
				}

				const accounts = await ctx.internalAdapter.findAccounts(userId);
				const account = accounts.find(
					(account) =>
						account.providerId === "credential" && Boolean(account.password),
				);
				const passwordHash = await ctx.password.hash(newPassword);
				if (account) {
					await ctx.internalAdapter.updateAccount(account.id, {
						password: passwordHash,
					});
				} else {
					await ctx.internalAdapter.linkAccount({
						userId,
						providerId: "credential",
						accountId: userId,
						password: passwordHash,
					});
				}

				if (options?.revokeSessions) {
					await ctx.internalAdapter.deleteUserSessions(userId);
				}
				return { status: true };
			});
		},
		createSession: async (options) => {
			return run(async (ctx) => {
				await requireUser(ctx, userId);
				const session = await ctx.internalAdapter.createSession(
					userId,
					options?.dontRememberMe,
				);
				return parseSessionOutput(ctx.options, session) as Session<
					Options["session"],
					Options["plugins"]
				>;
			});
		},
	});

	const createSessionScope = (
		token: string,
	): BetterAuthServerSessionAPI<Options> => ({
		get: async () => {
			return run(async (ctx) => {
				const session = await ctx.internalAdapter.findSession(token);
				if (!session) return null;
				if (session.session.expiresAt < new Date()) {
					await ctx.internalAdapter.deleteSession(token);
					return null;
				}
				return {
					session: parseSessionOutput(ctx.options, session.session) as Session<
						Options["session"],
						Options["plugins"]
					>,
					user: parseUserOutput(ctx.options, session.user) as User<
						Options["user"],
						Options["plugins"]
					>,
				};
			});
		},
		revoke: async () => {
			return run(async (ctx) => {
				await ctx.internalAdapter.deleteSession(token);
				return { status: true };
			});
		},
	});

	const serverAPI: BetterAuthServerCoreAPI<Options> & Record<string, unknown> =
		{
			user: createUserScope,
			getUser: createUserScope,
			session: createSessionScope,
		};

	for (const plugin of plugins) {
		if (!plugin.server) continue;
		const pluginServer = plugin.server(
			ctxPromise as unknown as Promise<AuthContext>,
			{
				run: run as unknown as <Result>(
					fn: (ctx: AuthContext) => Result | Promise<Result>,
				) => Promise<Result>,
			},
		);
		for (const [key, value] of Object.entries(pluginServer)) {
			if (key in serverAPI) {
				throw new Error(
					`Duplicate auth.server namespace "${key}" registered by plugin "${plugin.id}".`,
				);
			}
			serverAPI[key] = value;
		}
	}

	return serverAPI as BetterAuthServerAPI<Options>;
}
