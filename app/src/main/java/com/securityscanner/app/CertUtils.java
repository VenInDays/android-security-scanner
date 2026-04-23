package com.securityscanner.app;

import android.content.Context;
import android.util.Base64;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

/**
 * Generate a self-signed CA certificate for HTTPS MITM.
 * Uses only standard JCA APIs that work on Android.
 */
public class CertUtils {

    private static final String CERT_ALIAS = "SecurityScannerCA";
    private static final String CERT_FILE = "scanner_ca.crt";

    /**
     * Generate a self-signed CA certificate and save as PEM.
     */
    public static void generateAndSaveCert(Context context) {
        new Thread(() -> {
            try {
                File certDir = new File(context.getExternalFilesDir(null), "certs");
                if (!certDir.exists()) certDir.mkdirs();
                File certFile = new File(certDir, CERT_FILE);

                // Generate RSA key pair
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048, new SecureRandom());
                KeyPair keyPair = keyGen.generateKeyPair();

                Date now = new Date();
                Calendar cal = Calendar.getInstance();
                cal.setTime(now);
                cal.add(Calendar.YEAR, 10);
                Date notAfter = cal.getTime();

                X509Certificate cert = generateSelfSignedCert(keyPair, now, notAfter);
                byte[] certDer = cert.getEncoded();

                // Save as PEM
                FileOutputStream fos = new FileOutputStream(certFile);
                fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
                String b64 = Base64.encodeToString(certDer, Base64.NO_WRAP);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < b64.length(); i += 64) {
                    int end = Math.min(i + 64, b64.length());
                    sb.append(b64.substring(i, end)).append("\n");
                }
                fos.write(sb.toString().getBytes());
                fos.write("-----END CERTIFICATE-----\n".getBytes());
                fos.close();

                // Save keystore
                File ksFile = new File(certDir, "ca.keystore");
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(null, null);
                ks.setKeyEntry(CERT_ALIAS, keyPair.getPrivate(), "changeit".toCharArray(),
                        new java.security.cert.Certificate[]{cert});
                OutputStream os = new FileOutputStream(ksFile);
                ks.store(os, "changeit".toCharArray());
                os.close();

                android.os.Handler mainHandler = new android.os.Handler(android.os.Looper.getMainLooper());
                mainHandler.post(() -> Toast.makeText(context,
                        "Da tao chung chi CA thanh cong!", Toast.LENGTH_SHORT).show());

            } catch (final Exception e) {
                e.printStackTrace();
                android.os.Handler mainHandler = new android.os.Handler(android.os.Looper.getMainLooper());
                mainHandler.post(() -> Toast.makeText(context,
                        "Loi tao chung chi: " + e.getMessage(), Toast.LENGTH_LONG).show());
            }
        }).start();
    }

    /**
     * Generate a self-signed X509 certificate using standard Java APIs.
     * Uses a lightweight approach with java.security.cert.CertificateFactory.
     */
    private static X509Certificate generateSelfSignedCert(KeyPair keyPair, Date notBefore, Date notAfter)
            throws Exception {

        // Build a minimal DER-encoded X.509 certificate using raw ASN.1 encoding
        byte[] tbsCert = buildTbsCertificate(keyPair, notBefore, notAfter);
        byte[] signature = signData(keyPair.getPrivate(), tbsCert);
        byte[] certDer = assembleCertDer(tbsCert, signature, keyPair);

        java.security.cert.CertificateFactory cf =
                java.security.cert.CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
    }

    /**
     * Build the To Be Signed (TBS) portion of an X.509 certificate.
     */
    private static byte[] buildTbsCertificate(KeyPair keyPair, Date notBefore, Date notAfter) {
        try {
            // Build ASN.1 DER encoded TBS certificate
            java.io.ByteArrayOutputStream tbsOut = new java.io.ByteArrayOutputStream();

            // We'll construct a minimal but valid X.509v3 certificate
            // Version: v3 (explicit)
            byte[] versionTag = derTag(0xA0, derTag(2, derInteger(2)));
            // Serial number
            byte[] serial = derInteger(BigInteger.valueOf(System.currentTimeMillis()).toByteArray());
            // Signature algorithm: SHA256withRSA (OID 1.2.840.113549.1.1.11)
            byte[] sigAlg = derSequence(derOid(new byte[]{42, (byte) 134, 72, (byte) 134, 247, 13, 1, 1, 11}));
            // Issuer
            byte[] issuer = buildDistinguishedName("Security Scanner CA");
            // Validity
            byte[] validity = derSequence(derTime(notBefore), derTime(notAfter));
            // Subject
            byte[] subject = buildDistinguishedName("Security Scanner CA");
            // Subject Public Key Info
            byte[] spki = buildSubjectPublicKeyInfo(keyPair.getPublic());
            // Extensions: Basic Constraints (CA:true), Subject Key Identifier
            byte[] extensions = buildExtensions(keyPair.getPublic());

            // Assemble TBS
            tbsOut.write(versionTag);
            tbsOut.write(serial);
            tbsOut.write(sigAlg);
            tbsOut.write(issuer);
            tbsOut.write(validity);
            tbsOut.write(subject);
            tbsOut.write(spki);
            tbsOut.write(extensions);

            return tbsOut.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build TBS certificate", e);
        }
    }

    private static byte[] buildDistinguishedName(String cn) {
        try {
            // CN=Security Scanner CA, O=SecurityScanner
            byte[] cnSet = derSet(derSequence(
                    derOid(new byte[]{85, 4, 3}), // CN OID
                    derUtf8String(cn)));
            byte[] oSet = derSet(derSequence(
                    derOid(new byte[]{85, 4, 10}), // O OID
                    derUtf8String("SecurityScanner")));
            return derSequence(cnSet, oSet);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build DN", e);
        }
    }

    private static byte[] buildSubjectPublicKeyInfo(java.security.PublicKey pubKey) {
        try {
            byte[] keyBytes = pubKey.getEncoded(); // X.509 encoded
            return keyBytes; // SPKI is already the right format
        } catch (Exception e) {
            throw new RuntimeException("Failed to build SPKI", e);
        }
    }

    private static byte[] buildExtensions(java.security.PublicKey pubKey) {
        try {
            // Extensions sequence
            java.io.ByteArrayOutputStream extOut = new java.io.ByteArrayOutputStream();

            // Basic Constraints extension: CA=true
            byte[] basicConstraintsValue = derSequence(derBoolean(true), derInteger(-1));
            byte[] basicConstraints = derSequence(
                    derOid(new byte[]{55, 29, 19}), // basicConstraints OID
                    derOctetString(basicConstraintsValue));
            extOut.write(basicConstraints);

            // Subject Key Identifier extension
            byte[] skiValue = computeKeyId(pubKey);
            byte[] ski = derSequence(
                    derOid(new byte[]{55, 29, 14}), // subjectKeyIdentifier OID
                    derOctetString(skiValue));
            extOut.write(ski);

            // Key Usage extension: keyCertSign + cRLSign
            byte[] kuValue = derBitString(new byte[]{(byte) 0xA0}, 3); // bits 1,3,4 (unused, keyCertSign=5, cRLSign=6)
            byte[] ku = derSequence(
                    derOid(new byte[]{55, 29, 15}), // keyUsage OID
                    derOctetString(kuValue));
            extOut.write(ku);

            // Wrap in [3] EXPLICIT tag
            return derExplicitTag(3, extOut.toByteArray());
        } catch (Exception e) {
            // If extensions fail, return empty
            return new byte[0];
        }
    }

    private static byte[] computeKeyId(java.security.PublicKey pubKey) {
        try {
            java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-1");
            return sha.digest(pubKey.getEncoded());
        } catch (Exception e) {
            return new byte[20];
        }
    }

    private static byte[] signData(PrivateKey privateKey, byte[] data) throws Exception {
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    private static byte[] assembleCertDer(byte[] tbs, byte[] signature, KeyPair keyPair) {
        try {
            // Signature algorithm
            byte[] sigAlg = derSequence(derOid(new byte[]{42, (byte) 134, 72, (byte) 134, 247, 13, 1, 1, 11}));
            // Signature value
            byte[] sigValue = derBitString(signature);

            // Certificate = SEQUENCE { tbs, sigAlg, sigValue }
            return derSequence(tbs, sigAlg, sigValue);
        } catch (Exception e) {
            throw new RuntimeException("Failed to assemble cert DER", e);
        }
    }

    // ---- DER/ASN.1 encoding helpers ----

    private static byte[] derTag(int tag, byte[] value) {
        try {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            out.write(tag);
            writeLength(out, value.length);
            out.write(value);
            return out.toByteArray();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static byte[] derExplicitTag(int tagNum, byte[] value) {
        return derTag(0xA0 | tagNum, value);
    }

    private static byte[] derSequence(byte[]... elements) {
        try {
            java.io.ByteArrayOutputStream content = new java.io.ByteArrayOutputStream();
            for (byte[] e : elements) content.write(e);
            return derTag(0x30, content.toByteArray());
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static byte[] derSet(byte[]... elements) {
        try {
            java.io.ByteArrayOutputStream content = new java.io.ByteArrayOutputStream();
            for (byte[] e : elements) content.write(e);
            return derTag(0x31, content.toByteArray());
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static byte[] derInteger(byte[] value) {
        return derTag(0x02, value);
    }

    private static byte[] derInteger(int value) {
        return derTag(0x02, new byte[]{(byte) value});
    }

    private static byte[] derBoolean(boolean value) {
        return derTag(0x01, new byte[]{(byte) (value ? 0xFF : 0x00)});
    }

    private static byte[] derOid(byte[] oidBytes) {
        return derTag(0x06, oidBytes);
    }

    private static byte[] derUtf8String(String s) throws Exception {
        return derTag(0x0C, s.getBytes("UTF-8"));
    }

    private static byte[] derOctetString(byte[] value) {
        return derTag(0x04, value);
    }

    private static byte[] derBitString(byte[] value) {
        return derBitString(value, 0);
    }

    private static byte[] derBitString(byte[] value, int unusedBits) {
        try {
            byte[] tagged = new byte[value.length + 1];
            tagged[0] = (byte) unusedBits;
            System.arraycopy(value, 0, tagged, 1, value.length);
            return derTag(0x03, tagged);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static byte[] derTime(Date date) {
        String format = "yyMMddHHmmssZ";
        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat(format, java.util.Locale.US);
        sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        try {
            return derTag(0x17, sdf.format(date).getBytes("UTF-8"));
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static void writeLength(java.io.ByteArrayOutputStream out, int length) {
        if (length < 128) {
            out.write(length);
        } else if (length < 256) {
            out.write(0x81);
            out.write(length);
        } else if (length < 65536) {
            out.write(0x82);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        } else {
            out.write(0x83);
            out.write((length >> 16) & 0xFF);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        }
    }

    // ---- Public methods ----

    public static void installCertificate(Context context) {
        try {
            File certDir = new File(context.getExternalFilesDir(null), "certs");
            File certFile = new File(certDir, CERT_FILE);

            if (!certFile.exists()) {
                generateAndSaveCert(context);
                Toast.makeText(context, "Dang tao chung chi, vui long doi...",
                        Toast.LENGTH_SHORT).show();
                return;
            }

            android.net.Uri certUri = androidx.core.content.FileProvider.getUriForFile(
                    context, context.getPackageName() + ".fileprovider", certFile);

            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(certUri, "application/x-x509-ca-cert");
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);
        } catch (Exception e) {
            e.printStackTrace();
            openCertSettings(context);
        }
    }

    public static void openCertSettings(Context context) {
        try {
            Intent intent = new Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);
            Toast.makeText(context,
                    "Vui long chon 'Install from storage' de cai chung chi CA",
                    Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(context, "Khong the mo cai dat bao mat", Toast.LENGTH_SHORT).show();
        }
    }

    public static boolean isCertGenerated(Context context) {
        File certFile = new File(context.getExternalFilesDir(null), "certs/" + CERT_FILE);
        return certFile.exists();
    }

    public static String getKeyStorePath(Context context) {
        File ksFile = new File(context.getExternalFilesDir(null), "certs/ca.keystore");
        return ksFile.exists() ? ksFile.getAbsolutePath() : null;
    }
}
