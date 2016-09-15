package com.evonet;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

public class CertificateKey extends CordovaPlugin {

    public CertificateKey() {
    }

    private final static char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .toCharArray();

    private static int[] toInt = new int[128];

    static {
        for (int i = 0; i < ALPHABET.length; i++) {
            toInt[ALPHABET[i]] = i;
        }
    }

    private String encode(byte[] buf) {
        int size = buf.length;
        char[] ar = new char[((size + 2) / 3) * 4];
        int a = 0;
        int i = 0;
        while (i < size) {
            byte b0 = buf[i++];
            byte b1 = (i < size) ? buf[i++] : 0;
            byte b2 = (i < size) ? buf[i++] : 0;

            int mask = 0x3F;
            ar[a++] = ALPHABET[(b0 >> 2) & mask];
            ar[a++] = ALPHABET[((b0 << 4) | ((b1 & 0xFF) >> 4)) & mask];
            ar[a++] = ALPHABET[((b1 << 2) | ((b2 & 0xFF) >> 6)) & mask];
            ar[a++] = ALPHABET[b2 & mask];
        }
        switch (size % 3) {
            case 1:
                ar[--a] = '=';
            case 2:
                ar[--a] = '=';
        }
        return new String(ar);
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        try {
            try {
                try {
                    try {
                        try {
                            if (action.equals("getData")) {
                                return getData(args, callbackContext);
                            } else if (action.equals("listData")) {
                                return listData(args, callbackContext);
                            } else {
                                callbackContext.error("nenalezena pozadovana akce - " + action);
                            }
                        } catch (UnrecoverableKeyException e) {
                            e.printStackTrace();
                            callbackContext.error("Chyba při načítání souboru 1");
                            return false;
                        }
                    } catch (CertificateException e) {
                        e.printStackTrace();
                        callbackContext.error("Chyba při načítání souboru 2");
                        return false;
                    }
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                    callbackContext.error("Chyba při načítání souboru 3");
                    return false;
                }
            } catch (IOException e) {
                e.printStackTrace();
                callbackContext.error("Chyba při načítání souboru 4");
                return false;
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
            callbackContext.error("Chyba při načítání souboru 5");
            return false;
        }
        return true;
    }

    public boolean listData(JSONArray args, CallbackContext callbackContext) throws
            KeyStoreException,
            IOException,
            CertificateEncodingException,
            JSONException,
            NoSuchAlgorithmException,
            CertificateException,
            UnrecoverableKeyException {

        KeyStore keystore = KeyStore.getInstance("AndroidKeyStore");
        keystore.load(null);
        KeyStore.Entry entry = keystore.getEntry(args.getString(0), null);

        if (entry) {
            X509Certificate cert = (X509Certificate) keystore.getCertificate(args.getString(0));

            String pkey = "";
            try {
                pkey = encode(keystore.getKey(args.getString(0), args.getString(1).toCharArray()).getEncoded());
            } catch (UnrecoverableKeyException e) {
                e.printStackTrace();
                callbackContext.error("Chyba při generování klíče");
                return false;
            }
            String key = encode(cert.getEncoded());

            callbackContext.success(pkey + "|" + key);
            return true;
        } else {
            callbackContext.error("Nenalezen certifikát " + args.getString(0));
            return false;
        }
    }

    public boolean getData(JSONArray args, CallbackContext callbackContext) throws
            KeyStoreException,
            IOException,
            CertificateEncodingException,
            JSONException,
            NoSuchAlgorithmException,
            CertificateException,
            UnrecoverableKeyException {
        FileInputStream fIn = null;
        try {
            fIn = new FileInputStream(args.getString(0));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            callbackContext.error("Chyba při načítání souboru");
            return false;
        }

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try {
            keystore.load(fIn, args.getString(1).toCharArray());
        } catch (CertificateException e) {
            e.printStackTrace();
            callbackContext.error("Chyba při načítání obsahu souboru");
            return false;
        }
        Enumeration aliases = keystore.aliases();
        String keyAlias = "";
        while (aliases.hasMoreElements()) {
            keyAlias = (String) aliases.nextElement();
        }
        X509Certificate cert = (X509Certificate) keystore.getCertificate(keyAlias);

        String pkey = "";
        try {
            pkey = encode(keystore.getKey(keyAlias, args.getString(1).toCharArray()).getEncoded());
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
            callbackContext.error("Chyba při generování klíče");
            return false;
        }
        String key = encode(cert.getEncoded());

        callbackContext.success(pkey + "|" + key);
        return true;
    }
}
