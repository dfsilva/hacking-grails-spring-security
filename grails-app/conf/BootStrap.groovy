import hacking.OrgUser
import hacking.Organization
import hacking.Role
import hacking.User
import hacking.UserRole

class BootStrap {

	def init = { servletContext ->
		def adminRole = Role.findByAuthority('ROLE_ADMIN') ?: new Role(authority: 'ROLE_ADMIN').save()
		def userRole = Role.findByAuthority('ROLE_USER') ?: new Role(authority: 'ROLE_USER').save()

		def org1 = Organization.findByName('Org1') ?: new Organization(name: 'Org1').save()
		def org2 = Organization.findByName('Org2') ?: new Organization(name: 'Org2').save()

		if (!User.count()) {
			def admin = new User(username: 'admin', password: 'password', enabled: true).save()
			new OrgUser(user: admin, organization: org1).save()
			UserRole.create admin, adminRole

			def user = new User(username: 'user', password: 'password', enabled: true).save()
			new OrgUser(user: user, organization: org2).save()
			UserRole.create user, userRole

			def disabledUser = new User(username: 'disabled', password: 'password').save()
			new OrgUser(user: disabledUser, organization: org1).save()
			UserRole.create disabledUser, userRole
		}
	}
}
