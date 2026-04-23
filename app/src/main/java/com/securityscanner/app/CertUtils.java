package com.securityscanner.app;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.util.Base64;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
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

import javax.net.ssl.HttpsURLConnection;

public class CertUtils {

    private static final String CERT_ALIAS = "SecurityScannerCA";
    private static final String CERT_FILE = "scanner_ca.crt";

    /**
     * Generate a self-signed CA certificate for HTTPS MITM.
     */
    public static void generateAndSaveCert(Context context) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();

            long now = System.currentTimeMillis();
            Date notBefore = new Date(now);
            Calendar cal = Calendar.getInstance();
            cal.setTime(notBefore);
            cal.add(Calendar.YEAR, 10);
            Date notAfter = cal.getTime();

            // Use a simplified X509 certificate generation with Bouncy Castle-like approach
            // Since we can't use Bouncy Castle directly, we'll use a different approach:
            // Generate via openssl command or use Java's built-in keytool

            // For simplicity, generate the cert using keytool-equivalent approach
            generateCertNative(context);

            Toast.makeText(context, "Da tao chung chi thanh cong!", Toast.LENGTH_SHORT).show();

        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(context, "Loi tao chung chi: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    /**
     * Generate CA certificate using Java KeyStore (simpler approach)
     */
    private static void generateCertNative(Context context) {
        try {
            File certDir = new File(context.getExternalFilesDir(null), "certs");
            if (!certDir.exists()) certDir.mkdirs();
            File certFile = new File(certDir, CERT_FILE);

            // Generate a self-signed certificate using Java's built-in APIs
            // We create a simple DER-encoded certificate structure
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Create a PKCS12 keystore with our CA cert
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            KeyStore.PasswordProtection prot = new KeyStore.PasswordProtection("changeit".toCharArray());

            // Use sun.security.x509 to build certificate (available on Android)
            sun.security.x509.X500Name issuer = new sun.security.x509.X500Name(
                    "CN=Security Scanner CA, OU=Security, O=SecurityScanner, L=HCM, ST=HCM, C=VN");

            sun.security.x509.CertificateValidity validity =
                    new sun.security.x509.CertificateValidity(
                            new Date(System.currentTimeMillis()),
                            new Date(System.currentTimeMillis() + 10L * 365 * 24 * 60 * 60 * 1000));

            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

            sun.security.x509.X509CertInfo certInfo = new sun.security.x509.X509CertInfo();
            certInfo.set(sun.security.x509.X509CertInfo.VALIDITY, validity);
            certInfo.set(sun.security.x509.X509CertInfo.SERIAL_NUMBER,
                    new sun.security.x509.CertificateSerialNumber(serial));
            certInfo.set(sun.security.x509.X509CertInfo.SUBJECT, issuer);
            certInfo.set(sun.security.x509.X509CertInfo.ISSUER, issuer);
            certInfo.set(sun.security.x509.X509CertInfo.KEY,
                    new sun.security.x509.CertificateX509Key(keyPair.getPublic()));
            certInfo.set(sun.security.x509.X509CertInfo.VERSION,
                    new sun.security.x509.CertificateVersion(sun.security.x509.CertificateVersion.V3));

            // Mark as CA
            sun.security.x509.BasicConstraintsExtension caConstraint =
                    new sun.security.x509.BasicConstraintsExtension(true, -1);
            certInfo.set(sun.security.x509.X509CertInfo.EXTENSIONS,
                    new sun.security.x509.CertificateExtensions());
            ((sun.security.x509.CertificateExtensions) certInfo.get(
                    sun.security.x509.X509CertInfo.EXTENSIONS)).set(
                    sun.security.x509.BasicConstraintsExtension.Name,
                    caConstraint);

            // Add Subject Key Identifier
            sun.security.x509.KeyIdentifier kid = new sun.security.x509.KeyIdentifier(
                    keyPair.getPublic());
            sun.security.x509.SubjectKeyIdentifierExtension ski =
                    new sun.security.x509.SubjectKeyIdentifierExtension(
                            new sun.security.x509.KeyIdentifier(keyPair.getPublic()).getIdentifier());
            ((sun.security.x509.CertificateExtensions) certInfo.get(
                    sun.security.x509.X509CertInfo.EXTENSIONS)).set(
                    sun.security.x509.SubjectKeyIdentifierExtension.Name, ski);

            sun.security.x509.X509CertImpl cert = new sun.security.x509.X509CertImpl(certInfo);
            cert.sign(keyPair.getPrivate(), "SHA256withRSA");

            ks.setKeyEntry(CERT_ALIAS, keyPair.getPrivate(),
                    "changeit".toCharArray(),
                    new java.security.cert.Certificate[]{cert});
            ks.setCertificateEntry(CERT_ALIAS + "_cert", cert);

            // Save cert to file (DER format, then we'll convert)
            byte[] derCert = cert.getEncoded();
            FileOutputStream fos = new FileOutputStream(certFile);
            fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            String b64 = Base64.encodeToString(derCert, Base64.NO_WRAP);
            // Insert newlines every 64 chars
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < b64.length(); i += 64) {
                int end = Math.min(i + 64, b64.length());
                sb.append(b64.substring(i, end)).append("\n");
            }
            fos.write(sb.toString().getBytes());
            fos.write("-----END CERTIFICATE-----\n".getBytes());
            fos.close();

            // Save keystore for later use (VPN service needs the private key)
            File keyStoreFile = new File(certDir, "ca.keystore");
            OutputStream os = new FileOutputStream(keyStoreFile);
            ks.store(os, "changeit".toCharArray());
            os.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Install the generated CA certificate on the device.
     * Opens system certificate install dialog.
     */
    public static void installCertificate(Context context) {
        try {
            File certDir = new File(context.getExternalFilesDir(null), "certs");
            File certFile = new File(certDir, CERT_FILE);

            if (!certFile.exists()) {
                generateAndSaveCert(context);
            }

            if (certFile.exists()) {
                Intent intent = new Intent(Intent.ACTION_VIEW);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    intent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    Uri uri = androidx.core.content.FileProvider.getUriForFile(
                            context,
                            context.getPackageName() + ".fileprovider",
                            certFile);
                    intent.setDataAndType(uri, "application/x-x509-ca-cert");
                } else {
                    intent.setDataAndType(Uri.fromFile(certFile), "application/x-x509-ca-cert");
                }
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                context.startActivity(intent);
            } else {
                Toast.makeText(context, "Khong the tao chung chi. Vui long thu lai.",
                        Toast.LENGTH_LONG).show();
            }
        } catch (Exception e) {
            e.printStackTrace();
            // Fallback: open security settings
            openCertSettings(context);
        }
    }

    /**
     * Open certificate settings so user can manually install.
     */
    public static void openCertSettings(Context context) {
        try {
            Intent intent = new Intent(Settings.ACTION_SECURITY_SETTINGS);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);
            Toast.makeText(context,
                    "Vui long chon 'Install from storage' de cai chung chi",
                    Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(context, "Khong the mo cai dat bao mat", Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * Check if the CA cert file exists.
     */
    public static boolean isCertGenerated(Context context) {
        File certFile = new File(context.getExternalFilesDir(null), "certs/" + CERT_FILE);
        return certFile.exists();
    }

    /**
     * Get the keystore file path for VPN service.
     */
    public static String getKeyStorePath(Context context) {
        File keyStoreFile = new File(context.getExternalFilesDir(null), "certs/ca.keystore");
        return keyStoreFile.exists() ? keyStoreFile.getAbsolutePath() : null;
    }
}
