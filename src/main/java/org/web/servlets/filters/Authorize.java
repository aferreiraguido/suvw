package org.web.servlets.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.web.security.services.AuthenticationFactory;
import org.web.security.services.IAuthentication;

public class Authorize implements Filter {

	IAuthentication authentication = null;
	
	public void init(FilterConfig filterConfiguration) throws ServletException {
		String authenticationType = filterConfiguration.getInitParameter("authentication.type").toLowerCase();
		authentication = AuthenticationFactory.getAuthenticationObject(authenticationType);
		authentication.configureParameters(filterConfiguration);
		System.out.println("Authorize filter initialized! Using '" + authentication.getType() + "' for authentication.");
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, 
			FilterChain servletFilterChain) throws IOException, ServletException {
		
		HttpServletResponse response = (HttpServletResponse) servletResponse;
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpSession session = request.getSession();
		
		String authorizedUsername = (String) session.getAttribute("authorizedUsername");
		Boolean userIsAuthorized = authorizedUsername == null ? false : authorizedUsername.length() > 0;
		if (!userIsAuthorized) {
			if (authentication.performAuthentication()) {
				authorizedUsername = authentication.getUsername();
				session.setAttribute("authorizedUsername", authorizedUsername);
				System.out.println("User '" + authorizedUsername + "' is now authorized!");
				userIsAuthorized = true;
			} 
		} else {
			System.out.println("User '" + authorizedUsername + "' was previously authorized!");
		}
		
		if (userIsAuthorized) {
			servletFilterChain.doFilter(servletRequest, servletResponse);
		} else {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		}
	}

	public void destroy() {
		System.out.println("Authorize filter destroyed!");
	}

}