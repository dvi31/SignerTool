package com.dvic.signature.dsig;

import com.dvic.signature.dsig.XAdESProperties.SignaturePolicy;
import com.dvic.signature.util.DataTypes;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.MessageDigest;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.io.FilenameUtils;
import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class XMLSignature {

    //Signature method Type (SignatureMethod.RSA_SHA)
    public static final String SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public static final String xadesNS = "http://uri.etsi.org/01903/v1.3.2#";
    public static final String signedPropID = "SignProp1";
    private final XAdESProperties xAdESProperties = new XAdESProperties();

    public enum SignatureType {

        XMLDSIG,
        XADES
    };

    public enum SignatureFormat {

        MANIFEST,
        ENVELOPED,
        DETACHED,
        ENVELOPING
    };

    public enum C14nType {

        NONE,
        C14N_EXCL,
        C14N_EXCL_WITH_COMMENTS,
        C14N_INCL,
        C14N_INCL_WITH_COMMENTS
    };

    public enum InputType {

        BINARY,
        XML
    };

    public Document sign(String inFile, SignatureType type, SignatureFormat format, C14nType c14n,
            KeyStore.PrivateKeyEntry keyEntry, String sigId, SignaturePolicy signPolicy)
            throws MarshalException, NoSuchAlgorithmException, ParserConfigurationException, XMLSignatureException, Exception, InvalidAlgorithmParameterException {
        return sign(inFile, type, format, c14n, keyEntry, sigId, signPolicy, InputType.BINARY);
    }

    public Document sign(String inFile, SignatureType type, SignatureFormat format, C14nType c14n,
            KeyStore.PrivateKeyEntry keyEntry, String sigId, SignaturePolicy signPolicy, InputType inputType)
            throws MarshalException, NoSuchAlgorithmException, ParserConfigurationException, XMLSignatureException, Exception, InvalidAlgorithmParameterException {
        List objs = new ArrayList();
        List transform = null;
        List ref = new ArrayList();
        Node node;
        Document doc;
        String filename = FilenameUtils.getName(inFile);

        // Instantiate xml factory
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        switch (format) {
            case MANIFEST: {
                String canonicalizationMethod = getC14nMethod(c14n);

                ref.add(fac.newReference("#" + sigId + "_Manifest01",
                        fac.newDigestMethod(DigestMethod.SHA256, null),
                        Collections.singletonList(fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null)),
                        "http://www.w3.org/2000/09/xmldsig#Manifest", null));
                if (canonicalizationMethod != null) {
                    transform = Collections.singletonList(fac.newTransform(
                            canonicalizationMethod, (C14NMethodParameterSpec) null));
                }

                byte[] hash = computeXMLHash(inFile, c14n);
                Reference refDoc = fac.newReference(
                        filename,
                        fac.newDigestMethod(DigestMethod.SHA256, null),
                        transform,
                        null,
                        filename, hash);

                List listRefs = Collections.singletonList(refDoc);
                Manifest manifest = fac.newManifest(listRefs, sigId + "_Manifest01");
                objs.add(fac.newXMLObject(Collections.singletonList(manifest), null, null, null));

                // Instantiate empty doc to add signed manifest
                doc = dbf.newDocumentBuilder().newDocument();
                node = doc;
                break;
            }
            case DETACHED: {
                String canonicalizationMethod = getC14nMethod(c14n);

                if (canonicalizationMethod != null) {
                    transform = Collections.singletonList(fac.newTransform(
                            canonicalizationMethod, (C14NMethodParameterSpec) null));
                }

                byte[] hash = computeXMLHash(inFile, c14n);
                ref.add(fac.newReference(
                        filename,
                        fac.newDigestMethod(DigestMethod.SHA256, null),
                        transform,
                        null,
                        filename, hash));

                // Instantiate empty doc to add signed manifest
                doc = dbf.newDocumentBuilder().newDocument();
                node = doc;
                break;
            }
            case ENVELOPED: {
                final List<Transform> singletonList = new ArrayList<>();
                singletonList.add(fac.newTransform(Transform.ENVELOPED,
                        (TransformParameterSpec) null));

                String canonicalizationMethod = getC14nMethod(c14n);
                if (canonicalizationMethod != null) {
                    singletonList.add(fac.newTransform(
                            canonicalizationMethod, (C14NMethodParameterSpec) null));
                }

                // DSIG ENVELOPED all document (URI="")
                ref.add(fac.newReference("", fac.newDigestMethod(DigestMethod.SHA256, null),
                        singletonList,
                        null, null));

                // Instantiate document will be signed
                doc = dbf.newDocumentBuilder().parse(new FileInputStream(inFile));
                node = doc.getDocumentElement();
                break;
            }
            case ENVELOPING: {
                String canonicalizationMethod = getC14nMethod(c14n);
                if (canonicalizationMethod != null) {
                    transform = Collections.singletonList(fac.newTransform(
                            canonicalizationMethod, (C14NMethodParameterSpec) null));
                }
                ref.add(fac.newReference("#" + sigId + "_SignedDocument",
                        fac.newDigestMethod(DigestMethod.SHA256, null),
                        transform, "http://www.w3.org/2000/09/xmldsig#", null));

                // Instantiate document will be signed
                switch (inputType) {
                    case XML: {
                        Document signedDoc = dbf.newDocumentBuilder().parse(new FileInputStream(inFile));
                        Node signedNode = signedDoc.getDocumentElement();
                        XMLStructure content = new DOMStructure(signedNode);
                        objs.add(fac.newXMLObject(Collections.singletonList(content), sigId + "_SignedDocument", "application/xml", null));
                        //TODO MimeType="application/xml"
                        break;
                    }
                    default: {
                        String b64 = DataTypes.osB64StringFromFile(new File(inFile));
                        Document signedDoc = dbf.newDocumentBuilder().newDocument();
                        Node signedNode = signedDoc.createTextNode(b64);
                        XMLStructure content = new DOMStructure(signedNode);
                        objs.add(fac.newXMLObject(Collections.singletonList(content), sigId + "_SignedDocument", null, null));
                    }
                }

                // Instantiate empty doc to add signed doc
                doc = dbf.newDocumentBuilder().newDocument();
                node = doc;

                break;
            }
            default:
                return null;
        }

        //Init keyInfo used to sign
        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
        KeyInfo ki = createKeyInfo(fac, cert, sigId + "_KeyInfo");

        if (SignatureType.XADES.equals(type)) {
            objs.add(xAdESProperties.buildXAdESProperties(
                    fac, doc, sigId, signedPropID, cert, signPolicy));
            ref.add(fac.newReference("#" + signedPropID,
                    fac.newDigestMethod(DigestMethod.SHA256, null),
                    transform, "http://uri.etsi.org/01903/#SignedProperties", signedPropID + "Ref"));
        }

        // Create the SignedInfo.
        SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                        (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(SIGNATURE_METHOD, null),
                ref, sigId + "_SignedInfo");

        // Init DOMSignContext with sign key
        DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), node);
        dsc.putNamespacePrefix(javax.xml.crypto.dsig.XMLSignature.XMLNS, "ds");
//        dsc.putNamespacePrefix(XAdESProperties.xadesNS, "xad");
//        dsc.setDefaultNamespacePrefix("ds");

        // Create signature
        javax.xml.crypto.dsig.XMLSignature signature = fac.newXMLSignature(
                si, ki, objs, sigId, sigId + "_SignatureValue");
        signature.sign(dsc);

        return doc;
    }

    public static Element createElement(Document doc, String tag, String prefix, String nsURI) {
        String qName = prefix == null ? tag : prefix + ":" + tag;
        return doc.createElementNS(nsURI, qName);
    }

    public String getC14nMethod(C14nType c14n) {
        String canonicalizationMethod = null;
        switch (c14n) {
            case C14N_EXCL:
                canonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;
                break;
            case C14N_EXCL_WITH_COMMENTS:
                canonicalizationMethod = CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS;
                break;
            case C14N_INCL:
                canonicalizationMethod = CanonicalizationMethod.INCLUSIVE;
                break;
            case C14N_INCL_WITH_COMMENTS:
                canonicalizationMethod = CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS;
                break;
            case NONE:
                canonicalizationMethod = null;
                break;
        }
        return canonicalizationMethod;
    }

    public KeyInfo createKeyInfo(XMLSignatureFactory fac, X509Certificate cert, String id) {
        // Create KeyInfo containing the X509Data.
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List<Object> x509Content = new ArrayList<>();
        x509Content.add(cert.getSubjectX500Principal().getName());
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd), id);
        return ki;
    }

    public byte[] computeXMLHash(String file, C14nType c14n) throws Exception {
        try {
            File fs = new File(file);
            org.apache.xml.security.Init.init();
            byte[] data;
            switch (c14n) {
                case C14N_EXCL:
                    data = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
                            .canonicalize(DataTypes.osArrayFromFile(fs).toByteArray());
                    break;
                case C14N_EXCL_WITH_COMMENTS:
                    data = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS).
                            canonicalize(DataTypes.osArrayFromFile(fs).toByteArray());
                    break;
                case C14N_INCL:
                    data = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS).
                            canonicalize(DataTypes.osArrayFromFile(fs).toByteArray());
                    break;
                case C14N_INCL_WITH_COMMENTS:
                    data = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS).
                            canonicalize(DataTypes.osArrayFromFile(fs).toByteArray());
                    break;
                default:
                    data = DataTypes.osArrayFromFile(fs).toByteArray();
                    break;
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // Output the resulting document.
//            OutputStream os = new FileOutputStream("target/data_c14n.xml");
//            os.write(data);
//            os.close();
            return md.digest(data);
        } catch (IOException | NoSuchAlgorithmException ex) {
            System.err.println("Erreur de calcul de hash : " + ex.getMessage());
        }
        return null;
    }

    public KeyStore.PrivateKeyEntry loadKey(String keystore, String type, String password) throws Exception {
        // Load the KeyStore and get the signing key and certificate.
        KeyStore ks = KeyStore.getInstance(type);
        KeyStore.PrivateKeyEntry keyEntry = null;
        try (FileInputStream fs = new FileInputStream(keystore)) {
            ks.load(fs, password.toCharArray());
            final Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (ks.isKeyEntry(alias)) {
                    keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
                            new KeyStore.PasswordProtection(password.toCharArray()));
                    break;
                }
            }
        }
        if (keyEntry == null) {
            throw new RuntimeException("No private key entry found for " + keystore);
        }
        return keyEntry;
    }
}
