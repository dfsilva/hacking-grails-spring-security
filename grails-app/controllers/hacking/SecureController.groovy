package hacking

import grails.plugins.springsecurity.Secured

class SecureController {

	def index = {
		render 'not secured'
	}

	@Secured(['ROLE_ADMIN'])
	def admin = {
		render 'you have ROLE_ADMIN'
	}

	@Secured(['ROLE_USER'])
	def user = {
		render 'you have ROLE_USER'
	}

	@Secured(['ROLE_ADMIN', 'ROLE_USER'])
	def adminOrUser = {
		render 'you have ROLE_ADMIN or ROLE_USER'
	}
}
