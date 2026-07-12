import type { BetterAuthPlugin } from "@better-auth/core";
import { describe, expect, it } from "vitest";
import { betterAuth } from "../auth/full";
import { getTestInstance } from "../test-utils/test-instance";

describe("server API", async () => {
	it("merges plugin server namespaces and rejects duplicates", async () => {
		const plugin = {
			id: "server-plugin",
			server() {
				return {
					custom: {
						ping: () => "pong",
					},
				};
			},
		} satisfies BetterAuthPlugin;
		const auth = betterAuth({
			secret: "better-auth-secret-that-is-long-enough-for-validation-test",
			plugins: [plugin],
			logger: { disabled: true },
		});
		const custom = auth.server.custom as { ping: () => string };
		expect(custom.ping()).toBe("pong");

		const duplicatePlugin = {
			id: "duplicate-server-plugin",
			server() {
				return {
					user: {},
				};
			},
		} satisfies BetterAuthPlugin;
		expect(() =>
			betterAuth({
				secret: "better-auth-secret-that-is-long-enough-for-validation-test",
				plugins: [duplicatePlugin],
				logger: { disabled: true },
			}),
		).toThrow('Duplicate auth.server namespace "user"');
	});

	it("reads a user and linked accounts without request headers", async () => {
		const { auth, testUser } = await getTestInstance();
		const user = await auth.server.getUser("missing-user").get();
		expect(user).toBeNull();

		const session = await auth.api.signInEmail({
			body: {
				email: testUser.email,
				password: testUser.password,
			},
		});
		const scopedUser = await auth.server.user(session.user.id).get();
		expect(scopedUser).toMatchObject({
			id: session.user.id,
			email: testUser.email,
		});

		const accounts = await auth.server.getUser(session.user.id).listAccounts();
		expect(accounts).toHaveLength(1);
		expect(accounts[0]).toMatchObject({
			providerId: "credential",
			userId: session.user.id,
			scopes: [],
		});
		expect(accounts[0]).not.toHaveProperty("password");
		expect(accounts[0]).not.toHaveProperty("accessToken");
		expect(accounts[0]).not.toHaveProperty("refreshToken");
		expect(accounts[0]).not.toHaveProperty("idToken");
		expect(accounts[0]).not.toHaveProperty("scope");
	});

	it("updates users and manages sessions without request headers", async () => {
		const { auth, testUser } = await getTestInstance();
		const signIn = await auth.api.signInEmail({
			body: {
				email: testUser.email,
				password: testUser.password,
			},
		});
		const user = auth.server.getUser(signIn.user.id);

		const updated = await user.update({ name: "Headless User" });
		expect(updated).toMatchObject({
			id: signIn.user.id,
			name: "Headless User",
		});

		const createdSession = await user.createSession();
		expect(createdSession).toMatchObject({
			userId: signIn.user.id,
			token: expect.any(String),
		});

		const sessions = await user.listSessions();
		expect(sessions.map((session) => session.token)).toContain(
			createdSession.token,
		);

		await user.revokeSession(createdSession.token);
		const afterSingleRevoke = await user.listSessions();
		expect(afterSingleRevoke.map((session) => session.token)).not.toContain(
			createdSession.token,
		);

		const secondSession = await user.createSession();
		expect(secondSession.token).toBeDefined();
		const explicitSession = await auth.server
			.session(secondSession.token)
			.get();
		expect(explicitSession).toMatchObject({
			session: {
				token: secondSession.token,
				userId: signIn.user.id,
			},
			user: {
				id: signIn.user.id,
			},
		});
		await auth.server.session(secondSession.token).revoke();
		expect(await auth.server.session(secondSession.token).get()).toBeNull();

		await user.createSession();
		await user.revokeSessions();
		expect(await user.listSessions()).toHaveLength(0);
	});

	it("sets or replaces a credential password without request headers", async () => {
		const { auth, testUser } = await getTestInstance();
		const signIn = await auth.api.signInEmail({
			body: {
				email: testUser.email,
				password: testUser.password,
			},
		});

		await auth.server.getUser(signIn.user.id).setPassword("new-password-123");

		await expect(
			auth.api.signInEmail({
				body: {
					email: testUser.email,
					password: testUser.password,
				},
			}),
		).rejects.toThrow();

		const newPassword = await auth.api.signInEmail({
			body: {
				email: testUser.email,
				password: "new-password-123",
			},
		});
		expect(newPassword.user.id).toBe(signIn.user.id);
	});

	it("does not warn about a missing baseURL in headless mode", async () => {
		const logs: Array<{ level: string; message: string }> = [];
		const { auth } = await getTestInstance(
			{
				baseURL: undefined,
				headless: true,
				logger: {
					level: "warn",
					log(level, message) {
						logs.push({ level, message });
					},
				},
			},
			{
				disableTestUser: true,
			},
		);

		await auth.$context;

		expect(
			logs.some(
				(log) =>
					log.level === "warn" && log.message.includes("Base URL is not set"),
			),
		).toBe(false);
	});
});
