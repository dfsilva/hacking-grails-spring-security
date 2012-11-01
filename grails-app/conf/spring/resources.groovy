import hacking.extralogin.auth.OrganizationAuthenticationProvider
import hacking.extralogin.ui.OrganizationFilter
import hacking.logout.CustomLogoutSuccessHandler

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

beans = {

	def conf = SpringSecurityUtils.securityConfig

	// custom authentication
	authenticationProcessingFilter(OrganizationFilter) {
		authenticationManager = ref('authenticationManager')
		sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
		authenticationSuccessHandler = ref('authenticationSuccessHandler')
		authenticationFailureHandler = ref('authenticationFailureHandler')
		rememberMeServices = ref('rememberMeServices')
		authenticationDetailsSource = ref('authenticationDetailsSource')
		filterProcessesUrl = conf.apf.filterProcessesUrl
		usernameParameter = conf.apf.usernameParameter
		passwordParameter = conf.apf.passwordParameter
		continueChainBeforeSuccessfulAuthentication = conf.apf.continueChainBeforeSuccessfulAuthentication
		allowSessionCreation = conf.apf.allowSessionCreation
		postOnly = conf.apf.postOnly
	}

	// custom authentication
	daoAuthenticationProvider(OrganizationAuthenticationProvider) {
		passwordEncoder = ref('passwordEncoder')
		saltSource = ref('saltSource')
		preAuthenticationChecks = ref('preAuthenticationChecks')
		postAuthenticationChecks = ref('postAuthenticationChecks')
	}

	// custom logout redirect
	logoutSuccessHandler(CustomLogoutSuccessHandler) {
		redirectStrategy = ref('redirectStrategy')
		defaultTargetUrl = conf.logout.afterLogoutUrl
	}
}
