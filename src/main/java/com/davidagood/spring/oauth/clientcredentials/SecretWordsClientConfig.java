package com.davidagood.spring.oauth.clientcredentials;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

@ConfigurationProperties(prefix = "secret-words-client")
public class SecretWordsClientConfig {

	private final String url;

	@ConstructorBinding
	public SecretWordsClientConfig(String url) {
		this.url = url;
	}

	public String getUrl() {
		return url;
	}

}
