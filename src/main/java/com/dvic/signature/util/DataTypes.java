package com.dvic.signature.util;


import java.io.*;
import java.util.zip.*;
import org.apache.commons.codec.binary.Base64InputStream;
//import org.apache.commons.codec.binary.Base64InputStream;

public class DataTypes {
    private static final String newLine = System.getProperty("line.separator");
    
    private static ByteArrayOutputStream isToByteArrayOutputStream(InputStream is) throws IOException{
        ByteArrayOutputStream monFichier = new ByteArrayOutputStream();

        byte[] chunk = new byte[2048];
        int byteRead = 0;
        while((byteRead = is.read(chunk)) > -1)
        {
            monFichier.write(chunk, 0, byteRead);
        }
        is.close();
        return monFichier;
    }

    public static ByteArrayOutputStream osArrayFromFile(File leFichier) throws FileNotFoundException, IOException{
        FileInputStream monFis = new FileInputStream(leFichier);
        return isToByteArrayOutputStream(monFis);
    }

    public static ByteArrayOutputStream osDeflateArrayFromFile(File leFichier) throws FileNotFoundException, IOException {
        DeflaterInputStream monFis = new DeflaterInputStream(new FileInputStream(leFichier));
        return isToByteArrayOutputStream(monFis);
    }

    public static String osB64StringFromFile(File leFichier) throws FileNotFoundException, IOException {
        Base64InputStream monFis = new Base64InputStream(new FileInputStream(leFichier), true, 64, newLine.getBytes());
        return isToByteArrayOutputStream(monFis).toString();
    }

    public static String osB64DeflateStringFromFile(File leFichier) throws FileNotFoundException, IOException {
        Base64InputStream monFis = new Base64InputStream(new DeflaterInputStream(new FileInputStream(leFichier)), true, 64, newLine.getBytes());
        return isToByteArrayOutputStream(monFis).toString();
    }

    public static String osStringFromFile(File leFichier) throws FileNotFoundException, IOException {
        FileInputStream monFis = new FileInputStream(leFichier);
        return isToByteArrayOutputStream(monFis).toString();
    }

    public static String osStringFromFile(File leFichier, String charset) throws FileNotFoundException, IOException {
        FileInputStream monFis = new FileInputStream(leFichier);
        return isToByteArrayOutputStream(monFis).toString(charset);
    }
}
