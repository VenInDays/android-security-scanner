package com.securityscanner.app;

import android.content.Context;
import android.os.Build;
import android.util.Base64;

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
import android.widget.Toast;

/**
 * Generate a self-signed CA certificate for HTTPS MITM.
 * Uses standard JCA APIs with Bouncy Castle style encoding.
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

                // Create self-signed certificate using standard X509Certificate
                Date now = new Date();
                Calendar cal = Calendar.getInstance();
                cal.setTime(now);
                cal.add(Calendar.YEAR, 10);
                Date notAfter = cal.getTime();

                // Use javax.security to build a basic self-signed cert
                // We'll encode it manually as a DER certificate
                byte[] certDer = buildSelfSignedCert(
                        keyPair,
                        now,
                        notAfter,
                        "CN=Security Scanner CA, OU=Security, O=SecurityScanner, L=HCM, ST=HCM, C=VN"
                );

                // Save as PEM
                if (certDer != null && certDer.length > 0) {
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

                    // Also save keystore for VPN service use
                    saveKeyStore(certDir, keyPair, certDer);

                    android.os.Handler mainHandler = new android.os.Handler(android.os.Looper.getMainLooper());
                    mainHandler.post(() -> Toast.makeText(context,
                            "Da tao chung chi CA thanh cong!", Toast.LENGTH_SHORT).show());
                } else {
                    showCertError(context, "Khong the tao certificate DER");
                }

            } catch (final Exception e) {
                e.printStackTrace();
                android.os.Handler mainHandler = new android.os.Handler(android.os.Looper.getMainLooper());
                mainHandler.post(() -> showCertError(context, e.getMessage()));
            }
        }).start();
    }

    /**
     * Build a minimal DER-encoded X.509 self-signed certificate.
     */
    private static byte[] buildSelfSignedCert(KeyPair keyPair, Date notBefore, Date notAfter, String dn) {
        try {
            // Generate a self-signed cert via openssl subprocess (fallback for Android)
            // Alternative: Use a minimal DER builder
            return buildMinimalCertDer(keyPair, notBefore, notAfter, dn);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Build a minimal self-signed X.509 v3 certificate in DER format.
     * Uses raw ASN.1/DER encoding.
     */
    private static byte[] buildMinimalCertDer(KeyPair keyPair, Date notBefore, Date notAfter, String dn) {
        try {
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");

            // Use KeyStore to create a self-signed cert (simplest approach on Android)
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);

            // Generate cert with keytool-like behavior using KeyPairGenerator
            // On Android, we need to use a different approach
            // Let's use the built-in sun.security or Conscrypt APIs

            // Simplest working approach: Use Bouncy Castle if available, or fallback
            // to generating a PKCS12 keystore with a self-signed cert

            KeyStore p12 = KeyStore.getInstance("PKCS12");
            p12.load(null, null);

            // Create a certificate chain using java.security.cert.CertPathBuilder
            // This is the most portable approach
            javax.security.auth.x500.X500Principal principal =
                    new javax.security.auth.x500.X500Principal(dn);

            // Use internal API to generate cert (works on most Android devices)
            try {
                Class<?> x509CertClass = Class.forName("sun.security.x509.X509CertImpl");
                java.lang.reflect.Method signMethod = null;
                for (java.lang.reflect.Method m : x509CertClass.getMethods()) {
                    if (m.getName().equals("sign") && m.getParameterCount() == 2) {
                        signMethod = m;
                        break;
                    }
                }

                if (signMethod != null) {
                    // Full sun.security.x509 path
                    sun.security.x509.X500Name issuer = new sun.security.x509.X500Name(dn);
                    sun.security.x509.CertificateValidity validity =
                            new sun.security.x509.CertificateValidity(notBefore, notAfter);
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

                    // Mark as CA with basic constraints
                    sun.security.x509.CertificateExtensions ext = new sun.security.x509.CertificateExtensions();
                    ext.set(sun.security.x509.BasicConstraintsExtension.Name,
                            new sun.security.x509.BasicConstraintsExtension(true, -1));

                    // Subject Key Identifier
                    byte[] kidBytes = new sun.security.x509.KeyIdentifier(keyPair.getPublic()).getIdentifier();
                    ext.set(sun.security.x509.SubjectKeyIdentifierExtension.Name,
                            new sun.security.x509.SubjectKeyIdentifierExtension(kidBytes));

                    certInfo.set(sun.security.x509.X509CertInfo.EXTENSIONS, ext);

                    sun.security.x509.X509CertImpl cert = new sun.security.x509.X509CertImpl(certInfo);
                    signMethod.invoke(cert, keyPair.getPrivate(), "SHA256withRSA");

                    return cert.getEncoded();
                }
            } catch (ClassNotFoundException e) {
                // sun.security.x509 not available on this device
                // Fall through to alternative method
            }

            // Fallback: generate cert using openssl command
            return generateCertViaOpenssl(keyPair, notBefore, notAfter, dn);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Fallback: Generate cert using openssl (if available).
     */
    private static byte[] generateCertViaOpenssl(KeyPair keyPair, Date notBefore, Date notAfter, String dn) {
        try {
            // Use Java's built-in cert generation via KeyStore
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);

            // Use the java.security.cert.CertificateFactory approach
            // We create a self-signed certificate programmatically
            org.bouncycastle.asn1.x500.X500Name x500Name = null;

            // If Bouncy Castle is available
            try {
                Class.forName("org.bouncycastle.asn1.x500.X500Name");
                return generateCertBouncyCastle(keyPair, dn);
            } catch (ClassNotFoundException e) {
                // No Bouncy Castle either
            }

            // Last resort: generate via exec openssl
            File tempDir = new File(System.getProperty("java.io.tmpdir"), "cert_gen_" + System.currentTimeMillis());
            tempDir.mkdirs();

            // Write private key
            File keyFile = new File(tempDir, "ca.key");
            java.io.DataOutputStream dos = new java.io.DataOutputStream(new FileOutputStream(keyFile));
            byte[] privBytes = keyPair.getPrivate().getEncoded();
            // Simple PKCS8 encoding
            dos.write("-----BEGIN PRIVATE KEY-----\n".getBytes());
            dos.write(Base64.encode(privBytes, Base64.NO_WRAP).getBytes());
            dos.write("\n-----END PRIVATE KEY-----\n".getBytes());
            dos.close();

            // Write CSR config
            File configFile = new File(tempDir, "openssl.cnf");
            FileOutputStream fos = new FileOutputStream(configFile);
            String cnf = "[req]\ndistinguished_name=req_dn\nx509_extensions=v3_ca\n[req_dn]\nCN=Security Scanner CA\n[v3_ca]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n";
            fos.write(cnf.getBytes());
            fos.close();

            ProcessBuilder pb = new ProcessBuilder(
                    "openssl", "req", "-new", "-x509",
                    "-key", keyFile.getAbsolutePath(),
                    "-out", new File(tempDir, "ca.crt").getAbsolutePath(),
                    "-days", "3650",
                    "-subj", "/CN=Security Scanner CA/O=SecurityScanner",
                    "-config", configFile.getAbsolutePath()
            );
            pb.redirectErrorStream(true);
            Process p = pb.start();
            java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) output.append(line);
            p.waitFor();

            if (p.exitValue() == 0) {
                File certOut = new File(tempDir, "ca.crt");
                if (certOut.exists()) {
                    java.io.FileInputStream fis = new java.io.FileInputStream(certOut);
                    byte[] certBytes = new byte[(int) certOut.length()];
                    fis.read(certBytes);
                    fis.close();
                    // Cleanup
                    keyFile.delete();
                    configFile.delete();
                    certOut.delete();
                    tempDir.delete();
                    return certBytes;
                }
            }

            // Cleanup
            keyFile.delete();
            configFile.delete();
            tempDir.delete();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] generateCertBouncyCastle(KeyPair keyPair, String dn) {
        try {
            // Use Bouncy Castle if available
            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider());

            java.util.Calendar now = java.util.Calendar.getInstance();
            now.add(java.util.Calendar.YEAR, -1);

            org.bouncycastle.x509.X509V3CertificateGenerator certGen =
                    new org.bouncycastle.x509.X509V3CertificateGenerator();

            certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
            certGen.setIssuerDN(new javax.security.auth.x500.X500Principal(dn));
            certGen.setSubjectDN(new javax.security.auth.x500.X500Principal(dn));
            certGen.setNotBefore(now.getTime());
            certGen.setNotAfter(new Date(System.currentTimeMillis() + 10L * 365 * 24 * 60 * 60 * 1000));
            certGen.setPublicKey(keyPair.getPublic());
            certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

            certGen.addExtension(
                    org.bouncycastle.asn1.x509.X509Extensions.BasicConstraints,
                    true,
                    new org.bouncycastle.asn1.x509.BasicConstraints(true));

            certGen.addExtension(
                    org.bouncycastle.asn1.x509.X509Extensions.KeyUsage,
                    true,
                    new org.bouncycastle.asn1.x509.KeyUsage(
                            org.bouncycastle.asn1.x509.KeyUsage.keyCertSign |
                            org.bouncycastle.asn1.x509.KeyUsage.cRLSign));

            X509Certificate cert = certGen.generateX509Certificate(keyPair.getPrivate());
            return cert.getEncoded();

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void saveKeyStore(File certDir, KeyPair keyPair, byte[] certDer) {
        try {
            File ksFile = new File(certDir, "ca.keystore");
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);

            java.security.cert.CertificateFactory cf =
                    java.security.cert.CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(certDer));

            ks.setKeyEntry(CERT_ALIAS, keyPair.getPrivate(), "changeit".toCharArray(),
                    new java.security.cert.Certificate[]{cert});

            OutputStream os = new FileOutputStream(ksFile);
            ks.store(os, "changeit".toCharArray());
            os.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Install the generated CA certificate on the device.
     */
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

            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(
                    androidx.core.content.FileProvider.getUriForFile(
                            context,
                            context.getPackageName() + ".fileprovider",
                            certFile),
                    "application/x-x509-ca-cert");
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);

        } catch (Exception e) {
            e.printStackTrace();
            openCertSettings(context);
        }
    }

    /**
     * Open certificate settings so user can manually install.
     */
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

    private static void showCertError(Context context, String msg) {
        Toast.makeText(context, "Loi: " + msg, Toast.LENGTH_LONG).show();
    }
}
