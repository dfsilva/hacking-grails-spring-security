package hacking.extralogin

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken

class OrganizationAuthentication extends UsernamePasswordAuthenticationToken {

	private static final long serialVersionUID = 1

	final String organizationName

	OrganizationAuthentication(principal, credentials, String orgName) {
		super(principal, credentials)
		organizationName = orgName
	}

	OrganizationAuthentication(principal, credentials, String orgName, Collection authorities) {
		super(principal, credentials, authorities)
		organizationName = orgName
	}
}
