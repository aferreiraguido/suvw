package org.web.security.services.authentication;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.servlet.FilterConfig;

import org.web.security.services.IAuthentication;
import org.web.security.services.AuthenticationFactory.AuthenticationType;

import com.sun.jndi.ldap.LdapCtxFactory;

public class Ldap implements IAuthentication {
	
	String server = "";
	
	String principal = "";
	String credentials = "";
	
	String login = "";
	
	String username = "";
	
	public AuthenticationType getType() {
		return AuthenticationType.ldap;
	}

	public void configureParameters(FilterConfig filterConfiguration) {
		server = filterConfiguration.getInitParameter("ldap.server");
		
		login = filterConfiguration.getInitParameter("ldap.login");

		principal = filterConfiguration.getInitParameter("ldap.principal");
		credentials = filterConfiguration.getInitParameter("ldap.credentials");
	}

	public Object getParameterValue(String parameterName) {
		Object result = null;
		
		if (parameterName.equals("server")) {
			result = this.server;
		} else if (parameterName.equals("context")) {
			result = String.format("ldap://%s", this.server);
		} else if (parameterName.equals("principal")) {
			result = this.principal;
		} else if (parameterName.equals("credentials")) {
			result = this.credentials;
		} else if (parameterName.equals("login")) {
			result = this.login;
		}
		
		return result;
	}

	public Ldap() {
	}
	
	public String getUsername() {
		return this.username;
	}

	public Boolean requestUserCredentials() {
		return this.login != null && this.login.length() > 0;
	}

	public Boolean performAuthentication(String username, String password) {
		// check validity of username and password
		if (username.length() * password.length() <= 0) {
			return false;
		}
		
		String context = String.format("ldap://%s", this.server);
		
		Hashtable<String, String> ldapUserProperties = new Hashtable<String, String>();
		ldapUserProperties.put(Context.SECURITY_PRINCIPAL, username);
		ldapUserProperties.put(Context.SECURITY_CREDENTIALS, password);
	
		try {
			@SuppressWarnings("unused")
			DirContext directoryContext = LdapCtxFactory.getLdapCtxInstance(context, ldapUserProperties);
			
			this.username = username;
			System.out.println("Authentication succeeded!");
			
			return true;
		} catch (NamingException e) {
			System.out.println("Authentication failed!");
		}
		
		return false;
	}

	public Boolean performAuthentication() {
		return this.performAuthentication(this.principal, this.credentials);
	}
}
