package org.web.security.services;

import javax.servlet.FilterConfig;

import org.web.security.services.AuthenticationFactory.AuthenticationType;

public interface IAuthentication {

	public AuthenticationType getType();
	
	public void configureParameters(FilterConfig filterConfiguration);
	public Object getParameterValue(String parameterName);

	public Boolean requestUserCredentials();
	public Boolean performAuthentication(String username, String password);
	public Boolean performAuthentication();
	
	public String getUsername();

}
