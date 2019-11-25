package org.zz.gmhelper;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.zz.gmhelper.cert.SM2X509CertMaker;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;

//测试 p12证书
public class Test {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final char[] TEST_P12_PASSWD = "123456".toCharArray();
    private static final String TEST_P12_FILENAME = "target/ServerCA.p12";

    public static void main(String[] args) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            try (InputStream is = Files.newInputStream(Paths.get(TEST_P12_FILENAME),
                    StandardOpenOption.READ)) {
                ks.load(is, TEST_P12_PASSWD);
            }

            PrivateKey privateKey = (BCECPrivateKey) ks.getKey("server", TEST_P12_PASSWD);
            X509Certificate cert = (X509Certificate) ks.getCertificate("server");

            byte[] srcData = "1234567890123456789012345678901234567890".getBytes();

            // create signature
            Signature sign = Signature.getInstance(SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2, "BC");
            sign.initSign(privateKey);
            sign.update(srcData);
            byte[] signatureValue = sign.sign();

            // verify signature
            Signature verify = Signature.getInstance(SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2, "BC");
            verify.initVerify(cert);
            verify.update(srcData);
            boolean sigValid = verify.verify(signatureValue);
            System.out.println(sigValid);
        } catch (Exception ex) {
            ex.printStackTrace();

        }
    }
}
