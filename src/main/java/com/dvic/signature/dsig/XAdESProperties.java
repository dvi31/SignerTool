package com.dvic.signature.dsig;

import java.io.ByteArrayInputStream;
import java.security.cert.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class XAdESProperties {

    public static final String xadesNS = "http://uri.etsi.org/01903/v1.3.2#";
    public static final String signedPropID = "SignProp1";

    public static class SignaturePolicy {

        String policyOID;
        String policyDesc;
        String policyHashAlgo = DigestMethod.SHA256;
        String policyHash;

        public SignaturePolicy(String policyOID, String policyDesc, String policyHash) {
            this.policyOID = policyOID;
            this.policyDesc = policyDesc;
            this.policyHash = policyHash;
        }

        public SignaturePolicy(String policyOID, String policyDesc, String policyHashAlgo, String policyHash) {
            this.policyOID = policyOID;
            this.policyDesc = policyDesc;
            this.policyHashAlgo = policyHashAlgo;
            this.policyHash = policyHash;
        }

        public String getPolicyOID() {
            return policyOID;
        }

        public void setPolicyOID(String policyOID) {
            this.policyOID = policyOID;
        }

        public String getPolicyDesc() {
            return policyDesc;
        }

        public void setPolicyDesc(String policyDesc) {
            this.policyDesc = policyDesc;
        }

        public String getPolicyHashAlgo() {
            return policyHashAlgo;
        }

        public void setPolicyHashAlgo(String policyHashAlgo) {
            this.policyHashAlgo = policyHashAlgo;
        }

        public String getPolicyHash() {
            return policyHash;
        }

        public void setPolicyHash(String policyHash) {
            this.policyHash = policyHash;
        }

    }

    private Element createElementNS(Document doc, String namespaceuri, String qualifedName, String id) {
        Element elm = doc.createElementNS(namespaceuri, qualifedName);
        if (id != null) {
            elm.setAttributeNS(null, "Id", id);
            elm.setIdAttribute("Id", true);
        }
        return elm;
    }

    public XMLObject buildXAdESProperties(XMLSignatureFactory fac, Document doc,
            String signatureID, String signedPropID, X509Certificate cert,
            SignaturePolicy signaturePolicy)
            throws DatatypeConfigurationException, CertificateEncodingException,
            javax.security.cert.CertificateException, CertificateException {

        //QualifyingProperties
        Element QProp = createElementNS(doc, xadesNS, "xad:QualifyingProperties", null);
        QProp.setAttributeNS(null, "Target", "#" + signatureID);

        //SignedProperties
        Element SProp = createElementNS(doc, xadesNS, "xad:SignedProperties", signedPropID);
        QProp.appendChild(SProp);

        //SignedSignatureProperties
        Element SSP = createElementNS(doc, xadesNS, "xad:SignedSignatureProperties", null);
        SProp.appendChild(SSP);

        //SigningTime
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
        Element signingTime = createElementNS(doc, xadesNS, "xad:SigningTime", null);
        signingTime.setTextContent(sdf.format(new Date()));
        SSP.appendChild(signingTime);

        Element signingCertificate = buildSigningCertificate(doc, cert);
        SSP.appendChild(signingCertificate);

        if (signaturePolicy != null) {
            Element policyIdentifier = buildSignaturePolicyIdentifier(doc, signaturePolicy);
            SSP.appendChild(policyIdentifier);
        }

        //UnsignedProperties
        Element UPElement = createElementNS(doc, xadesNS, "xad:UnsignedProperties", null);
        QProp.appendChild(UPElement);

        DOMStructure qualifPropStruct = new DOMStructure(QProp);

        List xmlObj = new ArrayList();
        xmlObj.add(qualifPropStruct);
        XMLObject object = fac.newXMLObject(xmlObj, null, null, null);
        return object;
    }

    public Element buildSigningCertificate(Document doc, X509Certificate cert) throws CertificateEncodingException, CertificateException, DOMException {
        //SigningCertificate
        Element signingCertificate = doc.createElementNS(xadesNS, "xad:SigningCertificate");
        //Cert
        Element Cert = doc.createElementNS(xadesNS, "xad:Cert");
        signingCertificate.appendChild(Cert);

        //CertDigest
        Element CertDigest = createDSIGDigest(doc, "xad:CertDigest", 
                DigestMethod.SHA256, 
                Base64.encode(DigestUtils.sha256(cert.getEncoded())));
        Cert.appendChild(CertDigest);
        
        //IssuerSerial
        Element IssuerSerial = doc.createElementNS(xadesNS, "xad:IssuerSerial");
        Cert.appendChild(IssuerSerial);
        Element X509IssuerName = doc.createElementNS(xadesNS, "xad:X509IssuerName");
        IssuerSerial.appendChild(X509IssuerName);
        Element X509SerialNumber = doc.createElementNS(xadesNS, "xad:X509SerialNumber");
        IssuerSerial.appendChild(X509SerialNumber);
        X509IssuerName.setTextContent(cert.getIssuerDN().getName());
        if (cert.getIssuerX500Principal().getEncoded() != null) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            String der = "-----BEGIN CERTIFICATE-----\n"
                    + Base64.encode(cert.getEncoded()) + "\n-----END CERTIFICATE-----";
            X509Certificate issuer = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(
                    der.getBytes()));
            X509SerialNumber.setTextContent(issuer.getSerialNumber().toString());
        }
        return signingCertificate;
    }

    public Element buildSignaturePolicyIdentifier(Document doc, SignaturePolicy signaturePolicy) throws DOMException {
        //SignaturePolicyIdentifier
        Element SPI = doc.createElementNS(xadesNS, "xad:SignaturePolicyIdentifier");
        //SignaturePolicyId
        Element SPID = doc.createElementNS(xadesNS, "xad:SignaturePolicyId");
        SPI.appendChild(SPID);

        //SigPolicyId
        Element SigPID = doc.createElementNS(xadesNS, "xad:SigPolicyId");
        SPID.appendChild(SigPID);
        Element SigPIDId = doc.createElementNS(xadesNS, "xad:Identifier");
        SigPID.appendChild(SigPIDId);
        Element SigPIDDesc = doc.createElementNS(xadesNS, "xad:Description");
        SigPID.appendChild(SigPIDDesc);
        SigPIDId.setTextContent("urn:oid:" + signaturePolicy.getPolicyOID());
        SigPIDDesc.setTextContent(signaturePolicy.getPolicyDesc());

        //SigPolicyHash
        Element SigPHash = createDSIGDigest(doc, "xad:SigPolicyHash", 
                signaturePolicy.getPolicyHashAlgo(), 
                signaturePolicy.getPolicyHash());
        SPID.appendChild(SigPHash);

        return SPI;
    }

    private Element createDSIGDigest(Document doc, String qualifiedName, String algo, String hash) {
        Element dsigDgst = doc.createElementNS(xadesNS, qualifiedName);
        Element dgstMethod = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "ds:DigestMethod");
        dsigDgst.appendChild(dgstMethod);
        Element dgstVal = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "ds:DigestValue");
        dsigDgst.appendChild(dgstVal);
        dgstMethod.setAttributeNS(null, "Algorithm", algo);
        dgstVal.setTextContent(hash);
        return dsigDgst;
    }
}
