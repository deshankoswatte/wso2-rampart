package org.apache.rahas.impl.util;

/**
 * All SAML data retrieving call backs will implement this interface
 * 
 */
public interface SAMLCallback {
	
	/**
	 * Attribute callback
	 */
	int ATTR_CALLBACK = 1;
	
	/**
	 * Subject name identifier
	 */
	int NAME_IDENTIFIER_CALLBACK = 2;
	
	/**
	 * Returns the type of callback
	 * @return
	 */
	int getCallbackType();

}
