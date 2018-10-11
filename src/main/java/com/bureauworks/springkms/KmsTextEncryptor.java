package com.bureauworks.springkms;

import org.springframework.security.crypto.encrypt.TextEncryptor;

public class KmsTextEncryptor implements TextEncryptor {

    private final KmsUtils kmsUtils;
    private final String kmsId;

    public KmsTextEncryptor(final KmsUtils kmsUtils, final String kmsId) {
        this.kmsUtils = kmsUtils;
        this.kmsId = kmsId;
    }

    @Override
    public String encrypt(final String text) {
        return kmsUtils.encrypt(text, kmsId);
    }

    @Override
    public String decrypt(final String encryptedText) {
        return kmsUtils.decrypt(encryptedText);
    }

}
