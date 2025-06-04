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
    private static final String PUBLIC_KEY = "public_key";
    private static final String PRIVATE_KEY = "private_key";

    private static SharedPreferences prefs() {
        return ApplicationLoader.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public static void saveKeys(String publicKey, String privateKey) {
        prefs().edit().putString(PUBLIC_KEY, publicKey).putString(PRIVATE_KEY, privateKey).apply();
    }

    public static String getPublicKey() {
        return prefs().getString(PUBLIC_KEY, "");
    }

    public static String getPrivateKey() {
        return prefs().getString(PRIVATE_KEY, "");
    }

    public static boolean hasKeys() {
        return !TextUtils.isEmpty(getPublicKey()) && !TextUtils.isEmpty(getPrivateKey());
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

    public static String encrypt(String message) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            PGPPublicKey key = readPublicKey(new ByteArrayInputStream(getPublicKey().getBytes(StandardCharsets.UTF_8)));
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
}
