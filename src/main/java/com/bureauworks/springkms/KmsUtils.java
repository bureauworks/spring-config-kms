package com.bureauworks.springkms;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.*;
import com.amazonaws.util.BinaryUtils;
import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static java.util.stream.Collectors.toMap;

@Service
public class KmsUtils {

    public static final String DEFAULT_KEY_ALIAS = "alias/config-server";

    private final AWSKMS kmsClient;
    private final Map<String, KeyMetadata> kmsArnToKeyMetadataMap = new HashMap<>();

    private Map<String, String> kmsIdToAliasMap;

    public KmsUtils(final AWSKMS kmsClient) {
        this.kmsClient = kmsClient;
    }

    public String encrypt(final String plainText) {
        return encrypt(plainText, DEFAULT_KEY_ALIAS);
    }

    public String encrypt(final String plainText, final String keyId) {

        EncryptRequest request = new EncryptRequest()
                .withKeyId(keyId)
                .withPlaintext(ByteBuffer.wrap(plainText.getBytes()));

        EncryptResult result = kmsClient.encrypt(request);

        byte[] plaintextBytes = BinaryUtils.copyAllBytesFrom(result.getCiphertextBlob());

        return BinaryUtils.toBase64(plaintextBytes);

    }

    public String decrypt(final String secret) {

        DecryptResult response = getDecryptResult(secret);
        byte[] plaintextBytes = BinaryUtils.copyAllBytesFrom(response.getPlaintext());

        return new String(plaintextBytes, StandardCharsets.UTF_8);

    }

    public static class ResponseWithMetadata {

        public String kmsArn;
        public String kmsId;
        public String kmsAlias;
        public String decryptedValue;

        public ResponseWithMetadata(String kmsArn, String kmsId, String kmsAlias, String decryptedValue) {
            this.kmsArn = kmsArn;
            this.kmsId = kmsId;
            this.kmsAlias = kmsAlias;
            this.decryptedValue = decryptedValue;
        }

    }

    public ResponseWithMetadata decryptWithKeyMetadata(final String secret) {

        DecryptResult response = getDecryptResult(secret);
        byte[] plaintextBytes = BinaryUtils.copyAllBytesFrom(response.getPlaintext());
        String plainText = new String(plaintextBytes, StandardCharsets.UTF_8);

        // Actually, this property holds the key's arn (instead of the id)
        String keyArn = response.getKeyId();
        KeyMetadata keyMetadata = getKeyMetadata(keyArn);
        String kmsAlias = getKeyAlias(keyMetadata.getKeyId());

        return new ResponseWithMetadata(keyMetadata.getArn(), keyMetadata.getKeyId(), kmsAlias, plainText);

    }

    private String getKeyAlias(String keyId) {

        if (kmsIdToAliasMap == null) {
            kmsIdToAliasMap = kmsClient
                    .listAliases()
                    .getAliases()
                    .stream()
                    .filter(aliasListEntry -> Objects.nonNull(aliasListEntry.getTargetKeyId()))
                    .filter(aliasListEntry -> Objects.nonNull(aliasListEntry.getAliasName()))
                    .collect(toMap(AliasListEntry::getTargetKeyId, AliasListEntry::getAliasName));
        }

        return kmsIdToAliasMap.get(keyId);

    }

    private KeyMetadata getKeyMetadata(String keyArn) {

        KeyMetadata keyMetadata = kmsArnToKeyMetadataMap.get(keyArn);
        if (keyMetadata != null) {
            return keyMetadata;
        }

        DescribeKeyRequest describeKeyRequest = new DescribeKeyRequest().withKeyId(keyArn);
        keyMetadata = kmsClient.describeKey(describeKeyRequest).getKeyMetadata();
        kmsArnToKeyMetadataMap.put(keyArn, keyMetadata);

        return keyMetadata;
    }

    private DecryptResult getDecryptResult(String encryptedData) {

        byte[] encryptedBytes = BinaryUtils.fromBase64(encryptedData);
        DecryptRequest request = new DecryptRequest().withCiphertextBlob(ByteBuffer.wrap(encryptedBytes));

        return kmsClient.decrypt(request);

    }

}
