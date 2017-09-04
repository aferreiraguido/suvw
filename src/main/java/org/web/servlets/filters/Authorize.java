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
		
		// get authorized user from session
		String authorizedUsername = (String) session.getAttribute("authorizedUsername");
		Boolean userIsAuthorized = authorizedUsername == null ? false : authorizedUsername.length() > 0;

		String redirectUri = null;

		// perform authentication only if user is not previously authorized
		if (userIsAuthorized) {
			System.out.println("User '" + authorizedUsername + "' was previously authorized!");
		} else {
			if (request.getServletPath().equals(authentication.getParameterValue("login"))) {
				if (request.getMethod().equals("GET")) {
					// login URI is always allowed
					userIsAuthorized = true;
				} else if (request.getMethod().equals("POST")) {
					String username = request.getParameter("_login_username");
					String password = request.getParameter("_login_password");

					// authorize user with credentials provided from login page
					if (authentication.performAuthentication(username, password)) {
						authorizedUsername = authentication.getUsername();
						session.setAttribute("authorizedUsername", authorizedUsername);
						userIsAuthorized = true;
	
						System.out.println("User '" + authorizedUsername + "' is now authorized!");
					} else {
						redirectUri = String.format("%s%s", request.getContextPath(), authentication.getParameterValue("login"));
						session.setAttribute("_login_authentication_error", "Authentication error, username or password invalid!");
					}
				}
			} else {
				// redirect to login URI if configured
				if (authentication.requestUserCredentials()) {
					redirectUri = String.format("%s%s", request.getContextPath(), authentication.getParameterValue("login"));
					// keep original URL in session to redirect after valid authentication
					session.setAttribute("_login_original_request_url", request.getRequestURL());
				} else {
					// authorize user with credentials provided from initial parameters
					if (authentication.performAuthentication()) {
						authorizedUsername = authentication.getUsername();
						session.setAttribute("authorizedUsername", authorizedUsername);
						userIsAuthorized = true;
	
						System.out.println("User '" + authorizedUsername + "' is now authorized!");
					}
				}
			}
		}
		
		if (userIsAuthorized) {
			servletFilterChain.doFilter(servletRequest, servletResponse);
		} else {
			if (redirectUri == null) {
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			} else {
				response.sendRedirect(redirectUri);
			}
		}
	}

	public void destroy() {
		System.out.println("Authorize filter destroyed!");
	}

}