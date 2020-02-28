/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.rahas.impl;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.Token;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.opensaml.saml.saml2.core.Assertion;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;

import java.io.ByteArrayOutputStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import javax.xml.stream.XMLStreamException;

public class SAML2PassiveTokenIssuer extends SAML2TokenIssuer {

    private SAMLTokenIssuerConfig config = null;
    private RahasData data = null;
    
    public void setConfig(SAMLTokenIssuerConfig config) {
        this.config = config;
    }
    
    public OMElement issuePassiveRSTR(RahasData data) throws TrustException {

        MessageContext inMsgCtx = data.getInMessageContext();
        this.data = data;

        SOAPEnvelope env = TrustUtil.createSOAPEnvelope(inMsgCtx.getEnvelope().getNamespace().getNamespaceURI());

        Crypto crypto;

        try {
            if (config.cryptoElement != null) {

                crypto = CryptoFactory.getInstance(TrustUtil.toProperties(config.cryptoElement), inMsgCtx.getAxisService()
                        .getClassLoader(), null);
            } else if (config.cryptoPropertiesElement != null && config.cryptoPropertiesElement.getFirstElement() != null) {
                crypto = CryptoFactory.getInstance(
                        TrustUtil.toProperties(config.cryptoPropertiesElement.getFirstElement()), inMsgCtx.getAxisService()
                                .getClassLoader(), null);
            } else {
                crypto = CryptoFactory.getInstance(config.cryptoPropertiesFile, inMsgCtx.getAxisService().getClassLoader());
            }
        } catch (WSSecurityException e) {
            throw new TrustException("Error while extracting the crypto.", e);
        }

        // Creation and expiration times
        Date creationTime = new Date();
        Date expirationTime = new Date();
        expirationTime.setTime(creationTime.getTime() + config.ttl);

        // Get the document
        Document doc = ((Element) env).getOwnerDocument();

        // Get the key size and create a new byte array of that size
        int keySize = data.getKeysize();

        keySize = (keySize == -1) ? config.keySize : keySize;
        Assertion assertion = null;

        assertion = createBearerAssersion(config, doc, crypto, data);

        OMElement rstrcElem = null;
        OMElement rstrElem = null;
        int wstVersion = data.getVersion();
        if (RahasConstants.VERSION_05_02 == wstVersion) {
            rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(wstVersion, env.getBody());
        } else {
            rstrcElem = TrustUtil.createRequestSecurityTokenResponseCollectionElement(wstVersion, env.getBody());
            rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(wstVersion, rstrcElem);
        }

        TrustUtil.createTokenTypeElement(wstVersion, rstrElem).setText(RahasConstants.TOK_TYPE_SAML_20);

        if (config.addRequestedAttachedRef) {
            TrustUtil.createRequestedAttachedRef(wstVersion, rstrElem, "#" + assertion.getID(),
                    RahasConstants.TOK_TYPE_SAML_20);
        }

        if (config.addRequestedUnattachedRef) {
            TrustUtil.createRequestedUnattachedRef(wstVersion, rstrElem, assertion.getID(),
                    RahasConstants.TOK_TYPE_SAML_20);
        }

        if (data.getAppliesToAddress() != null) {
            TrustUtil.createAppliesToElement(rstrElem, data.getAppliesToAddress(), data.getAddressingNs());
        }

        // Use GMT time in milliseconds
        TimeZone timeZone = TimeZone.getTimeZone("UTC");
        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        dateFormat.setTimeZone(timeZone);

        // Add the Lifetime element
        TrustUtil.createLifetimeElement(wstVersion, rstrElem, dateFormat.format(creationTime), dateFormat.format(expirationTime));

        // Create the RequestedSecurityToken element and add the SAML token
        // to it
        OMElement reqSecTokenElem = TrustUtil.createRequestedSecurityTokenElement(wstVersion, rstrElem);
        Token assertionToken;

        Node tempNode = assertion.getDOM();

        // Serializing and re-generating the AXIOM element using the DOM Element created using xerces
        Element element = assertion.getDOM();

        ByteArrayOutputStream byteArrayOutputStrm = new ByteArrayOutputStream();

        DOMImplementationRegistry registry = null;
        try {
            registry = DOMImplementationRegistry.newInstance();
        } catch (ClassNotFoundException e) {
            throw new TrustException("errorCreatingSAMLToken", new String[]{assertion.getID()}, e);
        } catch (InstantiationException e) {
            throw new TrustException("errorCreatingSAMLToken", new String[]{assertion.getID()}, e);
        } catch (IllegalAccessException e) {
            throw new TrustException("errorCreatingSAMLToken", new String[]{assertion.getID()}, e);
        } catch (ClassCastException e) {
            throw new TrustException("errorCreatingSAMLToken", new String[]{assertion.getID()}, e);
        }

        DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");

        LSSerializer writer = impl.createLSSerializer();
        LSOutput output = impl.createLSOutput();
        output.setByteStream(byteArrayOutputStrm);
        writer.write(element, output);
        String elementString = byteArrayOutputStrm.toString();

        OMElement assertionElement = null;
        try {
            assertionElement = AXIOMUtil.stringToOM(elementString);
        } catch (XMLStreamException e) {
            throw new TrustException("errorCreatingSAMLToken", new String[]{assertion.getID()}, e);
        }

        reqSecTokenElem.addChild((OMNode) ((Element) rstrElem).getOwnerDocument().importNode(tempNode, true));

        // Store the token
        assertionToken = new Token(assertion.getID(), (OMElement) assertionElement, creationTime, expirationTime);

        // At this point we definitely have the secret
        // Otherwise it should fail with an exception earlier
        assertionToken.setSecret(data.getEphmeralKey());

        // SAML tokens are enabled for persistence only if token store is not disabled.
        if (!config.isTokenStoreDisabled()) {
            assertionToken.setPersistenceEnabled(true);
            TrustUtil.getTokenStore(inMsgCtx).add(assertionToken);
        }

        if (rstrcElem != null) {
            return rstrcElem;
        }

        return rstrElem;

    }
    
	public void setAudienceRestrictionCondition(String audienceRestriction)
			throws TrustException {
		this.audienceRestriction = audienceRestriction;

	}

    
}
