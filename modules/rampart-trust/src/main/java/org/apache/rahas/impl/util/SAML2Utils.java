/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.rahas.impl.util;

import net.shibboleth.utilities.java.support.codec.Base64Support;
import org.apache.axiom.om.impl.dom.jaxp.DocumentBuilderFactoryImpl;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.processor.EncryptedKeyProcessor;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialContextSet;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.*;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.carbon.identity.saml.common.util.SAMLInitializer;
import org.xml.sax.SAXException;

import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

public class SAML2Utils {

    private static Random random = new Random();
    private static final char[] charMapping = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p'};

    private static final Log log = LogFactory.getLog(SAML2Utils.class);

    public static Element getElementFromAssertion(XMLObject xmlObj) throws TrustException {
        try {

            String jaxpProperty = System.getProperty("javax.xml.parsers.DocumentBuilderFactory");
            System.setProperty("javax.xml.parsers.DocumentBuilderFactory", "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");

            MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObj);
            Element element = marshaller.marshall(xmlObj);

            // Reset the sys. property to its previous value.
            if (jaxpProperty == null) {
                System.getProperties().remove("javax.xml.parsers.DocumentBuilderFactory");
            } else {
                System.setProperty("javax.xml.parsers.DocumentBuilderFactory", jaxpProperty);
            }

            ByteArrayOutputStream byteArrayOutputStrm = new ByteArrayOutputStream();

            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();

            DOMImplementationLS impl =
                    (DOMImplementationLS) registry.getDOMImplementation("LS");

            LSSerializer writer = impl.createLSSerializer();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(byteArrayOutputStrm);
            writer.write(element, output);
            String elementString = byteArrayOutputStrm.toString();

            if (!TrustUtil.isDoomParserPoolUsed()) {
                DocumentBuilderFactoryImpl.setDOOMRequired(true);
            }
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(new ByteArrayInputStream(elementString.trim().getBytes()));
            Element assertionElement = document.getDocumentElement();
            if (!TrustUtil.isDoomParserPoolUsed()) {
                DocumentBuilderFactoryImpl.setDOOMRequired(false);
            }
            log.debug("DOM element is created successfully from the OpenSAML2 XMLObject");
            return assertionElement;

        } catch (Exception e) {
            throw new TrustException("Error creating DOM object from the assertion", e);
        }
    }

    /**
     * Extract certificates or the key available in the SAMLAssertion
     *
     * @param elem
     * @return the SAML2 Key Info
     * @throws org.apache.wss4j.common.ext.WSSecurityException
     */
    public static SAML2KeyInfo getSAML2KeyInfo(Element elem, Crypto crypto,
                                               CallbackHandler cb) throws WSSecurityException {
        Assertion assertion;

        // Build the assertion by unmarshalling the DOM element.
        try {
            SAMLInitializer.doBootstrap();

            String keyInfoElementString = elem.toString();
            DocumentBuilderFactory documentBuilderFactory = TrustUtil.getSecuredDocumentBuilderFactory();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(new ByteArrayInputStream(keyInfoElementString.trim().getBytes()));
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport
                    .getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory
                    .getUnmarshaller(element);
            assertion = (Assertion) unmarshaller
                    .unmarshall(element);
        } catch (InitializationException e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, e, "Failure in bootstrapping");
        } catch (UnmarshallingException e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, e, "Failure in unmarshelling the assertion");
        } catch (IOException e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, e, "Failure in unmarshelling the assertion");
        } catch (SAXException e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, e, "Failure in unmarshelling the assertion");
        } catch (ParserConfigurationException e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, e, "Failure in unmarshelling the assertion");
        }
        return getSAML2KeyInfo(assertion, crypto, cb);

    }

    public static SAML2KeyInfo getSAML2KeyInfo(Assertion assertion, Crypto crypto,
                                               CallbackHandler cb) throws WSSecurityException {

        //First ask the cb whether it can provide the secret
        WSPasswordCallback pwcb = new WSPasswordCallback(assertion.getID(), WSPasswordCallback.CUSTOM_TOKEN);
        if (cb != null) {
            try {
                cb.handle(new Callback[]{pwcb});
            } catch (Exception e1) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e1, "noKey", new Object[]{assertion.getID()});
            }
        }

        byte[] key = pwcb.getKey();

        if (key != null) {
            return new SAML2KeyInfo(assertion, key);
        } else {
            // if the cb fails to provide the secret.
            try {
                // extract the subject
                Subject samlSubject = assertion.getSubject();
                if (samlSubject == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                            "invalidSAML2Token", new Object[]{"for Signature (no Subject)"});
                }

                // extract the subject confirmation element from the subject
                SubjectConfirmation subjectConf = samlSubject.getSubjectConfirmations().get(0);
                if (subjectConf == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                            "invalidSAML2Token", new Object[]{"for Signature (no Subject Confirmation)"});
                }

                // Get the subject confirmation data, KeyInfoConfirmationDataType extends SubjectConfirmationData.
                SubjectConfirmationData scData = subjectConf.getSubjectConfirmationData();

                if (scData == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                            "invalidSAML2Token", new Object[]{"for Signature (no Subject Confirmation Data)"});
                }

                // Get the SAML specific XML representation of the keyInfo object
                XMLObject KIElem = null;
                List<XMLObject> scDataElements = scData.getOrderedChildren();
                Iterator<XMLObject> iterator = scDataElements.iterator();
                while (iterator.hasNext()) {
                    XMLObject xmlObj = iterator.next();
                    if (xmlObj instanceof org.opensaml.xmlsec.signature.KeyInfo) {
                        KIElem = xmlObj;
                        break;
                    }
                }

                Element keyInfoElement;

                // Generate a DOM element from the XMLObject.
                if (KIElem != null) {

                    // Set the "javax.xml.parsers.DocumentBuilderFactory" system property to make sure the endorsed JAXP
                    // implementation is picked over the default jaxp impl shipped with the JDK.
                    String jaxpProperty = System.getProperty("javax.xml.parsers.DocumentBuilderFactory");
                    System.setProperty("javax.xml.parsers.DocumentBuilderFactory", "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");

                    MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
                    Marshaller marshaller = marshallerFactory.getMarshaller(KIElem);
                    keyInfoElement = marshaller.marshall(KIElem);

                    // Reset the sys. property to its previous value.
                    if (jaxpProperty == null) {
                        System.getProperties().remove("javax.xml.parsers.DocumentBuilderFactory");
                    } else {
                        System.setProperty("javax.xml.parsers.DocumentBuilderFactory", jaxpProperty);
                    }

                } else {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                            "invalidSAML2Token", new Object[]{"for Signature (no key info element)"});
                }

                AttributeStatement attrStmt = assertion.getAttributeStatements().size() != 0 ?
                        assertion.getAttributeStatements().get(0) : null;
                AuthnStatement authnStmt = assertion.getAuthnStatements().size() != 0 ?
                        assertion.getAuthnStatements().get(0) : null;

                // if an attr stmt is present, then it has a symmetric key.
                if (attrStmt != null) {
                    NodeList children = keyInfoElement.getChildNodes();
                    int len = children.getLength();

                    for (int i = 0; i < len; i++) {
                        Node child = children.item(i);
                        if (child.getNodeType() != Node.ELEMENT_NODE) {
                            continue;
                        }
                        QName el = new QName(child.getNamespaceURI(), child.getLocalName());
                        if (el.equals(WSConstants.ENCRYPTED_KEY)) {

                            EncryptedKeyProcessor proc = new EncryptedKeyProcessor();
                            RequestData requestData = new RequestData();
                            requestData.setCallbackHandler(cb);
                            requestData.setDecCrypto(crypto);

                            proc.handleToken((Element) child, requestData);

                            return new SAML2KeyInfo(assertion, proc.getDecryptedBytes());
                        } else if (el.equals(new QName(WSConstants.WST_NS, "BinarySecret"))) {
                            Text txt = (Text) child.getFirstChild();
                            return new SAML2KeyInfo(assertion, Base64Support.decode(txt.getData()));
                        } else if (el.equals(new QName(WSConstants.SIG_NS, "X509Data"))) {
                            X509Certificate[] certs = null;
                            try {
                                KeyInfo ki = new KeyInfo(keyInfoElement, null);

                                if (ki.containsX509Data()) {
                                    X509Data data = ki.itemX509Data(0);
                                    XMLX509Certificate certElem = null;
                                    if (data != null && data.containsCertificate()) {
                                        certElem = data.itemCertificate(0);
                                    }
                                    if (certElem != null) {
                                        X509Certificate cert = certElem.getX509Certificate();
                                        certs = new X509Certificate[1];
                                        certs[0] = cert;
                                        return new SAML2KeyInfo(assertion, certs);
                                    }
                                }

                            } catch (XMLSecurityException e3) {
                                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e3,
                                        "invalidSAMLsecurity",
                                        new Object[]{"cannot get certificate (key holder)"});
                            }

                        }
                    }

                }

                // If an authn stmt is present then it has a public key.
                if (authnStmt != null) {

                    X509Certificate[] certs = null;
                    try {
                        KeyInfo ki = new KeyInfo(keyInfoElement, null);

                        if (ki.containsX509Data()) {
                            X509Data data = ki.itemX509Data(0);
                            XMLX509Certificate certElem = null;
                            if (data != null && data.containsCertificate()) {
                                certElem = data.itemCertificate(0);
                            }
                            if (certElem != null) {
                                X509Certificate cert = certElem.getX509Certificate();
                                certs = new X509Certificate[1];
                                certs[0] = cert;
                                return new SAML2KeyInfo(assertion, certs);
                            }
                        }

                    } catch (XMLSecurityException e3) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e3,
                                "invalidSAMLsecurity",
                                new Object[]{"cannot get certificate (key holder)"});
                    }

                }


                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                        "invalidSAMLsecurity",
                        new Object[]{"cannot get certificate or key "});

            } catch (MarshallingException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e,
                        "Failed marshalling the SAML Assertion");
            }
        }
    }

    public static String createID() {

        byte[] bytes = new byte[20]; // 160 bits
        random.nextBytes(bytes);

        char[] chars = new char[40];

        for (int i = 0; i < bytes.length; i++) {
            int left = (bytes[i] >> 4) & 0x0f;
            int right = bytes[i] & 0x0f;
            chars[i * 2] = charMapping[left];
            chars[i * 2 + 1] = charMapping[right];
        }

        return String.valueOf(chars);
    }

    public static void validateSignature(Assertion assertion, Crypto crypto) throws WSSecurityException {
        String alias = null;
        List x509Data = assertion.getSignature().getKeyInfo().getX509Datas();
        if (x509Data != null && x509Data.size() > 0) {
            org.opensaml.xmlsec.signature.X509Data x509Cred = (org.opensaml.xmlsec.signature.X509Data) x509Data.get(0);
            List x509Certs = x509Cred.getX509Certificates();
            if (x509Certs != null && x509Certs.size() > 0) {
                org.opensaml.xmlsec.signature.X509Certificate cert = (org.opensaml.xmlsec.signature.X509Certificate) x509Certs.get(0);

                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64Support.decode(cert.getValue())));
                    alias = crypto.getAliasForX509CertThumb(calculateThumbPrint(x509Certificate));
                    if (alias != null) {
                        class X509CredentialImpl implements X509Credential {
                            private PublicKey publicKey = null;

                            public X509CredentialImpl(X509Certificate cert) {
                                this.publicKey = cert.getPublicKey();
                            }

                            public X509Certificate getEntityCertificate() {
                                return null;
                            }

                            public Collection<X509Certificate> getEntityCertificateChain() {
                                return null;
                            }

                            public Collection<X509CRL> getCRLs() {
                                return null;
                            }

                            public String getEntityId() {
                                return null;
                            }

                            public UsageType getUsageType() {
                                return null;
                            }

                            public Collection<String> getKeyNames() {
                                return null;
                            }

                            public PublicKey getPublicKey() {
                                return this.publicKey;
                            }

                            public PrivateKey getPrivateKey() {
                                return null;
                            }

                            public SecretKey getSecretKey() {
                                return null;
                            }

                            public CredentialContextSet getCredentialContextSet() {
                                return null;
                            }

                            public Class<? extends Credential> getCredentialType() {
                                return null;
                            }
                        }

                        SignatureValidator.validate(assertion.getSignature(), new X509CredentialImpl(crypto.getCertificates(alias)[0]));
                    } else {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "SAMLTokenUntrustedSignatureKey");
                    }
                } catch (CertificateException var10) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, var10, "SAMLTokenErrorGeneratingX509CertInstance");
                } catch (SignatureException var11) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "SAMLTokenInvalidSignature");
                }
            } else {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "SAMLTokenInvalidX509Data");
            }
        } else {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "SAMLTokenInvalidX509Data");
        }
    }

    private static byte[] calculateThumbPrint(X509Certificate x509Certificate) {
        byte[] thumbPrintValue = new byte[0];

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(x509Certificate.getEncoded());
            thumbPrintValue = md.digest();
        } catch (NoSuchAlgorithmException var3) {
            var3.printStackTrace();
        } catch (CertificateEncodingException var4) {
            var4.printStackTrace();
        }

        return thumbPrintValue;
    }

}


