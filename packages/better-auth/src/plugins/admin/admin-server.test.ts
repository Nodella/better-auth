import { APIError, BASE_ERROR_CODES } from "@better-auth/core/error";
import { describe, expect, it } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { defaultRoles } from "./access";
import { admin } from "./admin";
import { ADMIN_ERROR_CODES } from "./error-codes";

describe("admin server API", async () => {
	it("creates, reads, lists, updates, and changes roles without request headers", async () => {
		const { auth } = await getTestInstance(
			{
				plugins: [admin({ roles: defaultRoles })],
			},
			{ disableTestUser: true },
		);

		const created = await auth.server.admin.createUser({
			email: "admin-server-user@test.com",
			name: "Admin Server User",
			password: "password123",
			role: "user",
		});
		expect(created.user).toMatchObject({
			email: "admin-server-user@test.com",
			name: "Admin Server User",
			role: "user",
		});

		const fetched = await auth.server.admin.getUser({
			userId: created.user.id,
		});
		expect(fetched.id).toBe(created.user.id);

		const listed = await auth.server.admin.listUsers({
			searchValue: "admin-server-user",
			searchField: "email",
		});
		expect(listed.users.map((user) => user.id)).toContain(created.user.id);
		expect(listed.total).toBeGreaterThanOrEqual(1);

		const updated = await auth.server.admin.updateUser({
			userId: created.user.id,
			data: {
				name: "Updated Server User",
				email: "updated-admin-server-user@test.com",
			},
		});
		expect(updated).toMatchObject({
			id: created.user.id,
			name: "Updated Server User",
			email: "updated-admin-server-user@test.com",
		});

		const role = await auth.server.admin.setRole({
			userId: created.user.id,
			role: "admin",
		});
		expect(role.user.role).toBe("admin");

		await expect(
			auth.server.admin.setRole({
				userId: created.user.id,
				role: "missing-role" as never,
			}),
		).rejects.toThrow(
			APIError.from(
				"BAD_REQUEST",
				ADMIN_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE,
			),
		);
	});

	it("bans, unbans, revokes sessions, sets passwords, and removes users", async () => {
		const { auth } = await getTestInstance(
			{
				plugins: [admin()],
			},
			{ disableTestUser: true },
		);

		const created = await auth.server.admin.createUser({
			email: "admin-server-lifecycle@test.com",
			name: "Admin Server Lifecycle",
		});
		await auth.server.admin.setUserPassword({
			userId: created.user.id,
			newPassword: "password123",
		});

		const signIn = await auth.api.signInEmail({
			body: {
				email: created.user.email,
				password: "password123",
			},
		});
		expect(signIn.user.id).toBe(created.user.id);

		const extraSession = await auth.server
			.getUser(created.user.id)
			.createSession();
		let sessions = await auth.server.admin.listUserSessions({
			userId: created.user.id,
		});
		expect(sessions.sessions.map((session) => session.token)).toContain(
			extraSession.token,
		);

		await auth.server.admin.revokeUserSession({
			sessionToken: extraSession.token,
		});
		sessions = await auth.server.admin.listUserSessions({
			userId: created.user.id,
		});
		expect(sessions.sessions.map((session) => session.token)).not.toContain(
			extraSession.token,
		);

		await auth.server.getUser(created.user.id).createSession();
		const banned = await auth.server.admin.banUser({
			userId: created.user.id,
			banReason: "server test",
			banExpiresIn: 60,
		});
		expect(banned.user).toMatchObject({
			id: created.user.id,
			banned: true,
			banReason: "server test",
		});
		expect(
			(await auth.server.admin.listUserSessions({ userId: created.user.id }))
				.sessions,
		).toHaveLength(0);

		const unbanned = await auth.server.admin.unbanUser({
			userId: created.user.id,
		});
		expect(unbanned.user).toMatchObject({
			id: created.user.id,
			banned: false,
			banReason: null,
			banExpires: null,
		});

		const session = await auth.server.getUser(created.user.id).createSession();
		await auth.server.admin.revokeUserSessions({ userId: created.user.id });
		expect(await auth.server.session(session.token).get()).toBeNull();

		await auth.server.admin.removeUser({ userId: created.user.id });
		await expect(
			auth.server.admin.getUser({ userId: created.user.id }),
		).rejects.toThrow(
			APIError.from("NOT_FOUND", BASE_ERROR_CODES.USER_NOT_FOUND),
		);
	});
});
