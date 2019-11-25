package com.whhx.input.util.envelope;

import java.io.Serializable;
import java.util.List;

public class EnvelopedData implements Serializable {

    private String version;
    private List<RecipientInfo> RecipientInfos;           //接受者集合
    private EncryptedContentInfo EncryptedContentInfo;    //加密的内容
    private Signeddata signeddata;                        //签名内容

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public List<RecipientInfo> getRecipientInfos() {
        return RecipientInfos;
    }

    public void setRecipientInfos(List<RecipientInfo> recipientInfos) {
        RecipientInfos = recipientInfos;
    }

    public EncryptedContentInfo getEncryptedContentInfo() {
        return EncryptedContentInfo;
    }

    public void setEncryptedContentInfo(EncryptedContentInfo encryptedContentInfo) {
        EncryptedContentInfo = encryptedContentInfo;
    }

    public Signeddata getSigneddata() {
        return signeddata;
    }

    public void setSigneddata(Signeddata signeddata) {
        this.signeddata = signeddata;
    }
}
