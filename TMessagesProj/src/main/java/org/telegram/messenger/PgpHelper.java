package org.telegram.messenger;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import java.util.Locale;
import java.security.SecureRandom;

public class PgpHelper {
    private static final String PREFS = "pgp_keys";
    private static final String PUBLIC_KEY_PREFIX = "public_key_";
    private static final String PRIVATE_KEY = "private_key";

    private static SharedPreferences prefs() {
        return ApplicationLoader.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public static void saveKeys(long dialogId, String publicKey, String privateKey) {
        SharedPreferences.Editor e = prefs().edit();
        if (publicKey != null) {
            e.putString(PUBLIC_KEY_PREFIX + dialogId, publicKey);
        }
        if (privateKey != null) {
            e.putString(PRIVATE_KEY, privateKey);
        }
        e.apply();
    }

    public static String getPublicKey(long dialogId) {
        return prefs().getString(PUBLIC_KEY_PREFIX + dialogId, "");
    }

    public static String getPrivateKey() {
        return prefs().getString(PRIVATE_KEY, "");
    }

    public static boolean hasKeys(long dialogId) {
        return !TextUtils.isEmpty(getPublicKey(dialogId)) && !TextUtils.isEmpty(getPrivateKey());
    }

    public static boolean hasPrivateKey() {
        return !TextUtils.isEmpty(getPrivateKey());
    }

    private static PGPPublicKey readPublicKey(InputStream in) throws Exception {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());
        Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
        while (rIt.hasNext()) {
            PGPPublicKeyRing kRing = rIt.next();
            Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
            while (kIt.hasNext()) {
                PGPPublicKey k = kIt.next();
                if (k.isEncryptionKey()) {
                    return k;
                }
            }
        }
        return null;
    }

    public static String encrypt(long dialogId, String message) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            PGPPublicKey key = readPublicKey(new ByteArrayInputStream(getPublicKey(dialogId).getBytes(StandardCharsets.UTF_8)));
            if (key == null) {
                return message;
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ArmoredOutputStream armoredOut = new ArmoredOutputStream(out);
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC"));
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(key).setProvider("BC"));
            OutputStream cOut = encGen.open(armoredOut, new byte[4096]);
            cOut.write(message.getBytes(StandardCharsets.UTF_8));
            cOut.close();
            armoredOut.close();
            return out.toString("UTF-8");
        } catch (Throwable e) {
            FileLog.e(e);
        }
        return message;
    }

    private static PGPSecretKey readSecretKey(InputStream in) throws Exception {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());
        Iterator<PGPSecretKey> keyRingIter = pgpSec.getKeyRings().next().getSecretKeys();
        while (keyRingIter.hasNext()) {
            PGPSecretKey key = keyRingIter.next();
            if (key.isSigningKey()) {
                return key;
            }
        }
        return null;
    }

    public static String decrypt(String message) {
        if (!hasPrivateKey() || TextUtils.isEmpty(message)) {
            return message;
        }
        try {
            Security.addProvider(new BouncyCastleProvider());
            InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
            org.bouncycastle.openpgp.PGPObjectFactory pgpFactory = new org.bouncycastle.openpgp.PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
            Object o = pgpFactory.nextObject();
            if (o instanceof org.bouncycastle.openpgp.PGPEncryptedDataList) {
                org.bouncycastle.openpgp.PGPEncryptedDataList encList = (org.bouncycastle.openpgp.PGPEncryptedDataList) o;
                Iterator<?> it = encList.getEncryptedDataObjects();
                PGPSecretKey secretKey = null;
                org.bouncycastle.openpgp.PGPPublicKeyEncryptedData pbe = null;
                while (it.hasNext()) {
                    pbe = (org.bouncycastle.openpgp.PGPPublicKeyEncryptedData) it.next();
                    secretKey = readSecretKey(new ByteArrayInputStream(getPrivateKey().getBytes(StandardCharsets.UTF_8)));
                    if (secretKey != null && secretKey.getKeyID() == pbe.getKeyID()) {
                        break;
                    }
                }
                if (secretKey != null) {
                    org.bouncycastle.openpgp.PGPPrivateKey privKey = secretKey.extractPrivateKey(new org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(new char[0]));
                    InputStream clear = pbe.getDataStream(new org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privKey));
                    org.bouncycastle.openpgp.PGPObjectFactory pgpFact = new org.bouncycastle.openpgp.PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
                    Object messageObj = pgpFact.nextObject();
                    if (messageObj instanceof org.bouncycastle.openpgp.PGPLiteralData) {
                        org.bouncycastle.openpgp.PGPLiteralData ld = (org.bouncycastle.openpgp.PGPLiteralData) messageObj;
                        ByteArrayOutputStream out = new ByteArrayOutputStream();
                        InputStream unc = ld.getInputStream();
                        int ch;
                        while ((ch = unc.read()) >= 0) {
                            out.write(ch);
                        }
                        return out.toString("UTF-8");
                    }
                }
            }
        } catch (Throwable e) {
            FileLog.e(e);
        }
        return message;
    }
}
