package com.bureauworks.springkms;

import com.amazonaws.services.kms.AWSKMSClientBuilder;
import org.springframework.cloud.config.server.encryption.TextEncryptorLocator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;

@Configuration
public class EncryptConfig {

    private final KmsUtils kmsUtils;
    private final HashMap<String, KmsTextEncryptor> kmsTextEncryptorHashMap = new HashMap<>();

    public EncryptConfig() {
        this.kmsUtils = new KmsUtils(AWSKMSClientBuilder.defaultClient());
    }

    @Bean
    public TextEncryptorLocator textEncryptorLocator() {
        return keys -> {

            String kmsKey = keys.getOrDefault("key", KmsUtils.DEFAULT_KEY_ALIAS);

            if (!kmsTextEncryptorHashMap.containsKey(kmsKey)) {
                kmsTextEncryptorHashMap.put(kmsKey, new KmsTextEncryptor(kmsUtils, kmsKey));
            }

            return kmsTextEncryptorHashMap.get(kmsKey);

        };
    }

}
