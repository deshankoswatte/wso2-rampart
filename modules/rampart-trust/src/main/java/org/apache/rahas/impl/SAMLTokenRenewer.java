package org.apache.rahas.impl;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.Parameter;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.TokenRenewer;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;

public abstract class SAMLTokenRenewer implements TokenRenewer {
    
    private String configParamName;

    private OMElement configElement;

    private String configFile;

    public abstract SOAPEnvelope renew(RahasData data) throws TrustException;

    /**
     * create the crypto from configuration. Used in SAML2tokenRenewer as well
     * @param inMsgCtx
     * @param config
     * @return
     */
    protected Crypto getCrypto(MessageContext inMsgCtx, SAMLTokenIssuerConfig config) throws TrustException {

        Crypto crypto;

        try {
            if (config.cryptoElement != null) {
                // Crypto props defined as elements.
                crypto = CryptoFactory.getInstance(TrustUtil
                        .toProperties(config.cryptoElement), inMsgCtx
                        .getAxisService().getClassLoader(), null);
            } else {
                // Crypto props defined in a properties file.
                crypto = CryptoFactory.getInstance(config.cryptoPropertiesFile,
                        inMsgCtx.getAxisService().getClassLoader());
            }
        } catch (WSSecurityException e) {
            throw new TrustException("Error occurred while extracting the crypto.", e);
        }
        return crypto;
    }

    /**
     * set the configuration for SAML 1.1 and 2.0 renewing
     * @param inMsgCtx
     * @return
     * @throws TrustException
     */
    protected SAMLTokenIssuerConfig setConfig(MessageContext inMsgCtx) throws TrustException {
        SAMLTokenIssuerConfig config = null;
        if (this.configElement != null) {
            config = new SAMLTokenIssuerConfig(configElement
                    .getFirstChildWithName(SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
        }
        // Look for the file
        if (config == null && this.configFile != null) {
            config = new SAMLTokenIssuerConfig(this.configFile);
        }
        // Look for the param
        if (config == null && this.configParamName != null) {
            Parameter param = inMsgCtx.getParameter(this.configParamName);
            if (param != null && param.getParameterElement() != null) {
                config = new SAMLTokenIssuerConfig(param
                        .getParameterElement().getFirstChildWithName(
                                SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
            } else {
                throw new TrustException("expectedParameterMissing",
                        new String[] { this.configParamName });
            }
        }
        if (config == null) {
            throw new TrustException("configurationIsNull");
        }
        if(config.isTokenStoreDisabled()){
            throw new TrustException("errorTokenStoreDisabled");
        }
        // Initialize and set token persister and config in configuration context.
        if (TokenIssuerUtil.isPersisterConfigured(config)) {
            TokenIssuerUtil.manageTokenPersistenceSettings(config, inMsgCtx);
        }
        return config;
    }

    /**
     * create the RSTR element with the token type
     * @param inMsgCtx
     * @param data
     * @param env
     * @param tokenType
     * @return
     * @throws TrustException
     */
    protected OMElement buildResponse(MessageContext inMsgCtx, RahasData data, SOAPEnvelope env, String tokenType) throws TrustException {
        // Create RSTR element, with respective version
        OMElement rstrElem;
        int wstVersion = data.getVersion();
        if (RahasConstants.VERSION_05_02 == wstVersion) {
            rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(
                    wstVersion, env.getBody());
        } else {
            OMElement rstrcElem = TrustUtil
                    .createRequestSecurityTokenResponseCollectionElement(
                            wstVersion, env.getBody());
            rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(
                    wstVersion, rstrcElem);
        }
        // Create TokenType element
        TrustUtil.createTokenTypeElement(wstVersion, rstrElem).setText(
                tokenType);
        return rstrElem;
    }

    /**
     * {@inheritDoc}
     */
    public void setConfigurationFile(String configFile) {
        this.configFile = configFile;
    }
    
    /**
     * {@inheritDoc}
     */
    public void setConfigurationElement(OMElement configElement) {
        this.configElement = configElement;
    }

    /**
     * {@inheritDoc}
     */
    public void setConfigurationParamName(String configParamName) {
        this.configParamName = configParamName;
    }


}
