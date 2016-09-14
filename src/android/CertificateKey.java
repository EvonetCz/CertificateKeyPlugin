package com.evonet;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

public class CertificateKey extends CordovaPlugin {

    public CertificateKey() {}

    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, InvalidKeySpecException {
        FileInputStream fIn = null;
        try {
            fIn = new FileInputStream(args.getString(0));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
          CallbackContext.error("Chyba při načítání souboru");
          return false;
        }

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(fIn, args.getString(1).toCharArray());
        Enumeration aliases = keystore.aliases();
        String keyAlias = "";
        while (aliases.hasMoreElements()) {
            keyAlias = (String) aliases.nextElement();
        }
        X509Certificate cert = (X509Certificate) keystore.getCertificate(keyAlias);

        String pkey = Base64.encode(keystore.getKey(keyAlias, args.getString(1).toCharArray()).getEncoded());
        String key = Base64.encode(cert.getEncoded());

        CallbackContext.success(pkey + "|" + key);
        return true;
    }
}
