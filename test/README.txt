****************************************
************* SignerTool 1.0 ***********
****************************************

Signature tool in java to sign in XMLDSIG or XADES (ENVELOPED, ENVELOPING, MANIFEST, DETACHED) with c14n transformation.

****************************************

Usage in interactive mode :
    java -jar SignerTool-1.0.jar

Usage with command line arguments

    REM Signature keystore
    set "KEYSTORE=Demo.p12"
    REM Signature keystore password
    set "KEYSTORE_PWD=password"
    REM Signature keystore type [PKCS12|JKS]
    set "KEYSTORE_TYPE=PKCS12"
    REM "Signature type [XADES|XMLDSIG]"
    set "TYPE=XADES" 
    REM Signature format [ENVELOPED|ENVELOPING|MANIFEST|DETACHED]
    set "FORMAT=ENVELOPED" 
    REM c14n type [NONE|C14N_EXCL|C14N_EXCL_WITH_COMMENTS|C14N_INCL|C14N_INCL_WITH_COMMENTS]
    set "C14N=C14N_EXCL" rem NONE, C14N_EXCL, C14N_EXCL_WITH_COMMENTS, C14N_INCL, C14N_INCL_WITH_COMMENTS
    REM Set signed content type. For DSIG ENVELOPING signature, XML will not base64 encode signed content before signing [XML|BINARY]
    set INPUT_TYPE=XML
    REM Signature xml id
    set SIG_ID="sig01"
    REM Signature policy id
    set POLICYID="1.2.3.4.5.6.7.8.9"
    REM Signature policy description
    set POLICYDESC="Signature policy"
    REM Signature policy digest
    set POLICYDGST="2jmj7l5rSw0yVb/vlWAYkK/YBwk="
    REM Signature policy digest method
    set POLICYDGSTMETHOD="http://www.w3.org/2000/09/xmldsig#sha1"
    

    java -Xbatch -classpath SignerTool-1.0.jar  com.dvic.signature.SignerTool ^
        --keystore "%KEYSTORE%" ^
        --keystorePwd "%KEYSTORE_PWD%" ^
        --keystoreType "%KEYSTORE_TYPE%" ^
        --infile "data.xml" ^
        --outFile "data_%TYPE%_%FORMAT%_%C14N%_%INPUT_TYPE%.xml" ^
        --type "%TYPE%" ^
        --format "%FORMAT%" ^
        --c14n "%C14N%" ^
        --inputType "%INPUT_TYPE%" ^
        --sigId "%SIG_ID%" ^
        --policyId "%POLICYID%" ^
        --policyDesc "%POLICYDESC%" ^
        --policyDgst "%POLICYDGST%" ^
        --policyHash "%POLICYDGSTMETHOD%"

