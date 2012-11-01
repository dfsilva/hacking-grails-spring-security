package hacking

class OrgUser {

	User user
	Organization organization

	static constraints = {
		organization unique: 'user'
	}
}
