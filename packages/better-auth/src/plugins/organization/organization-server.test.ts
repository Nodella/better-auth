import { describe, expect, it } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { organization } from "./organization";

describe("organization server API", async () => {
	it("manages organizations, members, invitations, and teams without request headers", async () => {
		const { auth } = await getTestInstance(
			{
				plugins: [
					organization({
						membershipLimit: 4,
						invitationLimit: 4,
						teams: {
							enabled: true,
						},
					}),
				],
			},
			{ disableTestUser: true },
		);

		const owner = await auth.api.signUpEmail({
			body: {
				email: "org-server-owner@test.com",
				password: "password123",
				name: "Org Server Owner",
			},
		});
		const memberUser = await auth.api.signUpEmail({
			body: {
				email: "org-server-member@test.com",
				password: "password123",
				name: "Org Server Member",
			},
		});

		const created = await auth.server.organization.createOrganization({
			userId: owner.user.id,
			name: "Server Org",
			slug: "server-org",
		});
		expect(created.organization).toMatchObject({
			name: "Server Org",
			slug: "server-org",
		});
		expect(created.member).toMatchObject({
			userId: owner.user.id,
			role: "owner",
		});
		expect(created.team).toMatchObject({
			organizationId: created.organization.id,
			name: "Server Org",
		});

		const listedForOwner = await auth.server.organization.listForUser({
			userId: owner.user.id,
		});
		expect(listedForOwner.organizations.map((org) => org.id)).toContain(
			created.organization.id,
		);

		const full = await auth.server.organization.getFullOrganization({
			organizationId: created.organization.id,
			includeTeams: true,
		});
		expect(full?.members).toHaveLength(1);
		expect(full?.teams?.map((team) => team.id)).toContain(created.team?.id);

		const updated = await auth.server.organization.updateOrganization({
			organizationId: created.organization.id,
			userId: owner.user.id,
			data: {
				name: "Updated Server Org",
				slug: "updated-server-org",
			},
		});
		expect(updated).toMatchObject({
			id: created.organization.id,
			name: "Updated Server Org",
			slug: "updated-server-org",
		});

		const addedMember = await auth.server.organization.addMember({
			organizationId: created.organization.id,
			userId: memberUser.user.id,
			role: "member",
			teamId: created.team?.id,
		});
		expect(addedMember).toMatchObject({
			organizationId: created.organization.id,
			userId: memberUser.user.id,
			role: "member",
		});

		const members = await auth.server.organization.listMembers({
			organizationId: created.organization.id,
		});
		expect(members.total).toBe(2);

		const updatedMember = await auth.server.organization.updateMember({
			memberId: addedMember.id,
			role: "admin",
		});
		expect(updatedMember.role).toBe("admin");

		const invitation = await auth.server.organization.createInvitation({
			organizationId: created.organization.id,
			email: "org-server-invitee@test.com",
			role: "member",
			inviterId: owner.user.id,
		});
		expect(invitation.invitation).toMatchObject({
			email: "org-server-invitee@test.com",
			status: "pending",
		});

		const invitations = await auth.server.organization.listInvitations({
			organizationId: created.organization.id,
		});
		expect(invitations.invitations.map((item) => item.id)).toContain(
			invitation.invitation.id,
		);

		const canceled = await auth.server.organization.cancelInvitation({
			invitationId: invitation.invitation.id,
			cancelledById: owner.user.id,
		});
		expect(canceled.invitation.status).toBe("canceled");

		const team = await auth.server.organization.createTeam({
			organizationId: created.organization.id,
			userId: owner.user.id,
			name: "Server Team",
		});
		expect(team).toMatchObject({
			organizationId: created.organization.id,
			name: "Server Team",
		});

		const fetchedTeam = await auth.server.organization.getTeam({
			teamId: team.id,
			organizationId: created.organization.id,
		});
		expect(fetchedTeam?.id).toBe(team.id);

		const updatedTeam = await auth.server.organization.updateTeam({
			teamId: team.id,
			userId: owner.user.id,
			data: {
				name: "Updated Server Team",
			},
		});
		expect(updatedTeam.name).toBe("Updated Server Team");

		const teams = await auth.server.organization.listTeams({
			organizationId: created.organization.id,
		});
		expect(teams.teams.map((item) => item.id)).toContain(team.id);

		const deletedTeam = await auth.server.organization.deleteTeam({
			teamId: team.id,
			userId: owner.user.id,
		});
		expect(deletedTeam.id).toBe(team.id);

		const removedMember = await auth.server.organization.removeMember({
			organizationId: created.organization.id,
			memberId: addedMember.id,
		});
		expect(removedMember.member.id).toBe(addedMember.id);

		const deleted = await auth.server.organization.deleteOrganization({
			organizationId: created.organization.id,
			userId: owner.user.id,
		});
		expect(deleted.id).toBe(created.organization.id);
		expect(
			await auth.server.organization.getOrganization({
				organizationId: created.organization.id,
			}),
		).toBeNull();
	});
});
