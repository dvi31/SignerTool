package com.dvic.signature;

import com.dvic.signature.util.DataTypes;
import java.io.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.UnknownHostException;
import java.security.*;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
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
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.commons.io.FilenameUtils;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class SignerTool {

    public enum SignatureType {

        MANIFEST,
        DSIG_ENVELOPED
    };

    public enum C14nType {

        NONE,
        C14N_EXCL,
        C14N_EXCL_WITH_COMMENTS,
        C14N_INCL,
        C14N_INCL_WITH_COMMENTS
    };

    @Option(name = "--keystore", required = false, usage = "Keystore")
    private File keystore = null;

    @Option(name = "--keystorePwd", required = false, usage = "Keystore password")
    private String keystorePwd = null;

    @Option(name = "--keystoreType", required = false, usage = "Keystore type [PKCS12, JKS]")
    private String keystoreType = null;

    @Option(name = "--infile", required = false, usage = "File to sign")
    private File inFile = null;

    @Option(name = "--outFile", required = false, usage = "Signed file")
    private File outFile = null;

    @Option(name = "--type", required = false, usage = "Signature type [MANIFEST|DSIG]")
    private SignatureType type = null;

    @Option(name = "--c14n", required = false, usage = "c14n type [NONE|C14N_EXCL|C14N_EXCL_WITH_COMMENTS|C14N_INCL|C14N_INCL_WITH_COMMENTS]")
    private C14nType c14n = null;

    public static void main(String[] args) {
        SignerTool monAppel = new SignerTool();
        monAppel.parseAndRun(args);
    }

    public void parseAndRun(String[] arguments) {
        CmdLineParser monParseur = new CmdLineParser(this);

        try {
            monParseur.parseArgument(arguments);

            String ksPath = keystore != null ? keystore.getAbsolutePath()
                    : getParam("Keystore", "Demo.p12");
            keystorePwd = keystorePwd != null ? keystorePwd
                    : getParam("Keystore Password", "password");
            keystoreType = keystoreType != null ? keystoreType
                    : getParam("Keystore Type", "PKCS12");

            String inPath = inFile != null ? inFile.getAbsolutePath()
                    : getParam("File to sign", "data.xml");

            type = type != null ? type : SignatureType.valueOf(
                    getParam("Signature type [MANIFEST|DSIG]", "MANIFEST"));

            if (type == SignatureType.MANIFEST) {
                c14n = c14n != null ? c14n : C14nType.valueOf(
                        getParam("c14n type [NONE|C14N_EXCL|C14N_EXCL_WITH_COMMENTS|"
                                + "C14N_INCL|C14N_INCL_WITH_COMMENTS]", "C14N_EXCL"));
            }

            String outPath = FilenameUtils.removeExtension(inPath) + "_" + type.name() + ".xml";
            outPath = outFile != null ? outFile.getAbsolutePath()
                    : getParam("File to save signature", outPath);

            System.out.println("SignerTool parameters :");
            System.out.println("\tkeystore     : " + ksPath);
            System.out.println("\tinFile       : " + inPath);
            System.out.println("\toutFile      : " + outPath);
            System.out.println("\ttype         : " + type);
            System.out.println("\tc14n         : " + c14n);
            System.out.println();

            // Get key and signing certificate
            KeyStore.PrivateKeyEntry keyEntry = loadKey(ksPath, keystoreType, keystorePwd);
            Document doc = sign(inPath, type, c14n, keyEntry);
            if (doc != null) {
                System.out.println("Signature successful !!!");
                System.out.println();
            }

            // Output the resulting document.
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            if (outPath != null) {
                OutputStream os = new FileOutputStream(outPath);
                trans.transform(new DOMSource(doc), new StreamResult(os));
                System.out.println("outFile       : " + outPath);
            } else {
                StringWriter writer = new StringWriter();
                trans.transform(new DOMSource(doc), new StreamResult(writer));
                System.out.println(writer.getBuffer().toString());
            }

        } catch (CmdLineException ex) {
            System.err.println("Erreur : " + ex.getMessage());
            monParseur.printUsage(System.err);
        } catch (UnknownHostException ex) {
            System.err.println("Erreur de résolution du nom de machine : " + ex.getMessage());
        } catch (FileNotFoundException ex) {
            System.err.println("Erreur de lecture du fichier : " + ex.getMessage());
        } catch (IOException ex) {
            System.err.println("Erreur d\'E/S : " + ex.getMessage());
        } catch (Exception ex) {
            if (ex.getCause() != null) {
                System.err.println("Erreur : " + ex.getCause().getMessage());
            } else {
                System.err.println("Erreur : " + ex.getMessage());
            }
        }
    }

    public Document sign(String inFile, SignatureType type, C14nType c14n, KeyStore.PrivateKeyEntry keyEntry) throws MarshalException, NoSuchAlgorithmException, ParserConfigurationException, XMLSignatureException, Exception, InvalidAlgorithmParameterException {
        List objs = new ArrayList();
        List transform = null;
        Reference ref;
        Node node;
        Document doc;

        // Instantiate xml factory
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        switch (type) {
            case MANIFEST:
                String canonicalizationMethod = getC14nMethod(c14n);

                ref = fac.newReference("#Manifest01", fac.newDigestMethod(DigestMethod.SHA256, null),
                        Collections.singletonList(fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null)),
                        "http://www.w3.org/2000/09/xmldsig#Manifest", null);
                if (canonicalizationMethod != null) {
                    transform = Collections.singletonList(fac.newTransform(
                            canonicalizationMethod, (C14NMethodParameterSpec) null));
                }

                byte[] hash = computeXMLHash(inFile, c14n);
                Reference refDoc = fac.newReference(
                        "#file01",
                        fac.newDigestMethod(DigestMethod.SHA256, null),
                        transform,
                        "http://www.w3.org/2000/09/xmldsig#file01",
                        "file01", hash);

                List listRefs = Collections.singletonList(refDoc);
                Manifest manifest = fac.newManifest(listRefs, "Manifest01");
                objs.add(fac.newXMLObject(Collections.singletonList(manifest), null, null, null));

                // Instantiate empty doc to add signed manifest
                doc = dbf.newDocumentBuilder().newDocument();
                node = doc;
                break;
            case DSIG_ENVELOPED:
                // DSIG ENVELOPED all document (URI="")
                ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA256, null),
                        Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
                        null, null);

                // Instantiate document will be signed
                doc = dbf.newDocumentBuilder().parse(new FileInputStream(inFile));
                node = doc.getDocumentElement();
                break;
            default:
                return null;
        }
        // Create the SignedInfo.
        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(
                CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) null), fac
                .newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

        //Init keyInfo used to sign
        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
        KeyInfo ki = createKeyInfo(fac, cert);

        // Init DOMSignContext with sign key
        DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), node);
        dsc.putNamespacePrefix(XMLSignature.XMLNS, "dsig");

        // Create signature
        XMLSignature signature = fac.newXMLSignature(si, ki, objs, null, null);
        signature.sign(dsc);

        return doc;
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

    public KeyInfo createKeyInfo(XMLSignatureFactory fac, X509Certificate cert) {
        // Create KeyInfo containing the X509Data.
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List<Object> x509Content = new ArrayList<>();
        x509Content.add(cert.getSubjectX500Principal().getName());
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
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

    private String getParam(String paramName, String defaultVal) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Enter " + paramName + " (default " + defaultVal + "):");
        String s = br.readLine();
        return !"".equals(s) ? s : defaultVal;
    }
}
