package com.dvic.signature;

import com.dvic.signature.SignerTool.C14nType;
import com.dvic.signature.SignerTool.SignatureType;
import java.io.*;
import java.security.*;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.junit.Test;
import org.w3c.dom.Document;

/**
 * Unit test for simple App.
 */
public class SignerToolTest extends SignerTool {
    //https://community.oracle.com/thread/1538592?start=0&tstart=0
    //http://www.oracle.com/technetwork/articles/javase/dig-signature-api-140772.html

    public static final String KEYSTORE = "src/test/resources/Demo.p12";
    public static final String KEYSTORE_PWD = "password";
    public static final String KEYSTORE_TYPE = "PKCS12";

    @Test
    public void manifestC14N_EXCL() throws Exception {
        String inFile = this.getClass().getResource("/data.xml").getPath();
        String outFile = "target/MANIFEST_C14N_EXCL.xml";

        //get key and signing certificate
        KeyStore.PrivateKeyEntry keyEntry = loadKey(KEYSTORE, KEYSTORE_TYPE, KEYSTORE_PWD);
        Document doc = sign(inFile, SignatureType.MANIFEST, C14nType.C14N_EXCL, keyEntry);

        // Output the resulting document.
        if (outFile != null) {
            OutputStream os = new FileOutputStream(outFile);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(os));
        }
    }

    @Test
    public void manifestC14N_EXCL_WITH_COMMENTS() throws Exception {
        String inFile = this.getClass().getResource("/data.xml").getPath();
        String outFile = "target/MANIFEST_C14N_EXCL_WITH_COMMENTS.xml";

        //get key and signing certificate
        KeyStore.PrivateKeyEntry keyEntry = loadKey(KEYSTORE, KEYSTORE_TYPE, KEYSTORE_PWD);
        Document doc = sign(inFile, SignatureType.MANIFEST, C14nType.C14N_EXCL_WITH_COMMENTS, keyEntry);

        // Output the resulting document.
        if (outFile != null) {
            OutputStream os = new FileOutputStream(outFile);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(os));
        }
    }

    @Test
    public void DSIG() throws Exception {
        String inFile = this.getClass().getResource("/data.xml").getPath();
        String outFile = "target/DSIG_ENVELOPED_C14N_EXCL.xml";

        //get key and signing certificate
        KeyStore.PrivateKeyEntry keyEntry = loadKey(KEYSTORE, KEYSTORE_TYPE, KEYSTORE_PWD);
        Document doc = sign(inFile, SignatureType.DSIG_ENVELOPED, null, keyEntry);

        // Output the resulting document.
        if (outFile != null) {
            OutputStream os = new FileOutputStream(outFile);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(os));
        }
    }

}
