package org.web.security.services;

import org.web.security.services.authentication.Ldap;

public class AuthenticationFactory {

	public enum AuthenticationType { internal, ldap }
	
	public AuthenticationFactory() {
	}
	
	public static IAuthentication getAuthenticationObject(String authenticationTypeValue) {

		IAuthentication result = null;
		
		try {
			AuthenticationType authenticationType = AuthenticationType.valueOf(authenticationTypeValue);
			
			if (authenticationType.equals(AuthenticationType.internal)) {
			} else if (authenticationType.equals(AuthenticationType.ldap)) {
				result = new Ldap();
			}
		} catch (Exception e) {
		}

		return result;
	}
}
