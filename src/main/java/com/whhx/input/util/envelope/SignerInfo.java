package com.whhx.input.util.envelope;


import com.whhx.input.util.crypto.Signature;

import java.io.Serializable;

public class SignerInfo implements Serializable {

    private String version;
    private String issuerAndSerialNumber;      //证书颁发者可识别的证书序列号
    private String digestAlgorithms;           //摘要计算算法
    private String authenticatedAttributes;    //签名者签名的属性集合
    private String digestEncryptionAlgorithm;  //sm2数字签名算法标识符
    private Signature encryptedDigest;            //签名者私钥进行的签名结果

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getIssuerAndSerialNumber() {
        return issuerAndSerialNumber;
    }

    public void setIssuerAndSerialNumber(String issuerAndSerialNumber) {
        this.issuerAndSerialNumber = issuerAndSerialNumber;
    }

    public String getDigestAlgorithms() {
        return digestAlgorithms;
    }

    public void setDigestAlgorithms(String digestAlgorithms) {
        this.digestAlgorithms = digestAlgorithms;
    }

    public String getAuthenticatedAttributes() {
        return authenticatedAttributes;
    }

    public void setAuthenticatedAttributes(String authenticatedAttributes) {
        this.authenticatedAttributes = authenticatedAttributes;
    }

    public String getDigestEncryptionAlgorithm() {
        return digestEncryptionAlgorithm;
    }

    public void setDigestEncryptionAlgorithm(String digestEncryptionAlgorithm) {
        this.digestEncryptionAlgorithm = digestEncryptionAlgorithm;
    }

    public Signature getEncryptedDigest() {
        return encryptedDigest;
    }

    public void setEncryptedDigest(Signature encryptedDigest) {
        this.encryptedDigest = encryptedDigest;
    }
}
