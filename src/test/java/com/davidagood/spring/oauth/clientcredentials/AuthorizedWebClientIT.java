package com.davidagood.spring.oauth.clientcredentials;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.endpoint.DefaultOAuth2TokenRequestParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.json.JsonCompareMode;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import static com.davidagood.spring.oauth.clientcredentials.AuthorizedWebClientConfig.REGISTRATION_ID;
import static com.davidagood.spring.oauth.clientcredentials.TestUtil.getFreePort;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AuthorizedWebClientIT {

	static final String DUMMY_ACCESS_TOKEN = "dummy-access-token";

	private static final int MOCK_SERVER_PORT = getFreePort();

	private static final Instant FIXED_TIMESTAMP = LocalDate.of(2020, 1, 8)
		.atStartOfDay()
		.atZone(ZoneId.of("America/New_York"))
		.toInstant();

	private static MockWebServer mockWebServer;

	@Autowired
	MockMvc mockMvc;

	@Autowired
	@Qualifier("oauth2RestClient")
	RestClient oauth2RestClient;

	@Autowired
	ObjectMapper objectMapper;

	@Autowired
	ClientRegistrationRepository clientRegistrationRepository;

	@MockitoSpyBean
	@Qualifier("authorizationServerAuthorizationSuccessHandler")
	OAuth2AuthorizationSuccessHandler authorizationServerAuthorizationSuccessHandler;

	@MockitoSpyBean
	@Qualifier("authorizationServerAuthorizationFailureHandler")
	OAuth2AuthorizationFailureHandler authorizationServerAuthorizationFailureHandler;

	@MockitoSpyBean
	@Qualifier("resourceServerAuthorizationFailureHandler")
	OAuth2AuthorizationFailureHandler resourceServerAuthorizationFailureHandler;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry r) {
		r.add("secret-words-client.url", () -> "http://localhost:" + MOCK_SERVER_PORT);
		r.add("spring.security.oauth2.client.provider.my-client-provider.token-uri",
				() -> "http://localhost:" + MOCK_SERVER_PORT);
	}

	@BeforeEach
	void setUp() throws IOException {
		mockWebServer = new MockWebServer();
		mockWebServer.start(MOCK_SERVER_PORT);
	}

	@AfterEach
	void tearDown() throws IOException {
		mockWebServer.close();
	}

	@Test
	void shouldGetOauthTokenJustOnceWhenRequestsAreSerialized() throws Exception {
		// Given
		var secretWords = List.of("speakers", "keyboard");
		var expected = SecretWordsDto.from(secretWords, FIXED_TIMESTAMP);
		int repetitions = 10;

		mockWebServer.enqueue(createAuthServerGrantRequestSuccessResponse());
		for (int i = 0; i < repetitions; i++) {
			mockWebServer.enqueue(createResourceServerSuccessResponse(secretWords));
		}

		// When
		for (int i = 0; i < repetitions; i++) {
			mockMvc.perform(get("/api/words"))
				.andExpect(status().isOk())
				.andExpect(MockMvcResultMatchers.content()
					.json(objectMapper.writeValueAsString(expected), JsonCompareMode.STRICT));
		}

		// Then
		verify(authorizationServerAuthorizationSuccessHandler, times(1)).onAuthorizationSuccess(any(), any(), any());

		RecordedRequest authServerRequest = mockWebServer.takeRequest();
		assertThat(authServerRequest.getRequestUrl()).isEqualTo(HttpUrl.parse(
				clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID).getProviderDetails().getTokenUri()));
		assertThat(authServerRequest.getHeader(HttpHeaders.CONTENT_TYPE))
			.isEqualTo(new MediaType(MediaType.APPLICATION_FORM_URLENCODED).toString());

		RecordedRequest firstResourceServerRequest = mockWebServer.takeRequest();
		assertThat(firstResourceServerRequest.getHeader(HttpHeaders.AUTHORIZATION))
			.isEqualTo(String.format("%s %s", BEARER.getValue(), DUMMY_ACCESS_TOKEN));
	}

	@Test
	void shouldGetOauthTokenJustOnceWhenRequestsAreParallelize() throws Exception {
		// Given
		var secretWords = List.of("speakers", "keyboard");
		var expected = SecretWordsDto.from(secretWords, FIXED_TIMESTAMP);
		int repetitions = 10;

		mockWebServer.enqueue(createAuthServerGrantRequestSuccessResponse());
		for (int i = 0; i < repetitions; i++) {
			mockWebServer.enqueue(createResourceServerSuccessResponse(secretWords));
		}

		var jsonBody = objectMapper.writeValueAsString(expected);
		var threads = new Thread[repetitions];
		for (int i = 0; i < repetitions; i++) {
			threads[i] = new Thread(() -> {
				try {
					mockMvc.perform(get("/api/words"))
						.andExpect(status().isOk())
						.andExpect(MockMvcResultMatchers.content().json(jsonBody, JsonCompareMode.STRICT));
				}
				catch (Exception e) {
					e.printStackTrace();
				}
			});
		}

		// When
		for (int i = 0; i < repetitions; i++) {
			threads[i].start();
		}

		for (int i = 0; i < repetitions; i++) {
			threads[i].join();
		}

		// Then
		verify(authorizationServerAuthorizationSuccessHandler, times(1)).onAuthorizationSuccess(any(), any(), any());

		RecordedRequest authServerRequest = mockWebServer.takeRequest();
		assertThat(authServerRequest.getRequestUrl()).isEqualTo(HttpUrl.parse(
				clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID).getProviderDetails().getTokenUri()));
		assertThat(authServerRequest.getHeader(HttpHeaders.CONTENT_TYPE))
			.isEqualTo(new MediaType(MediaType.APPLICATION_FORM_URLENCODED).toString());

		RecordedRequest firstResourceServerRequest = mockWebServer.takeRequest();
		assertThat(firstResourceServerRequest.getHeader(HttpHeaders.AUTHORIZATION))
			.isEqualTo(String.format("%s %s", BEARER.getValue(), DUMMY_ACCESS_TOKEN));
	}

	MockResponse createResourceServerSuccessResponse(List<String> secretWords) throws JsonProcessingException {
		return new MockResponse().setResponseCode(200)
			.setHeader(CONTENT_TYPE, APPLICATION_JSON_VALUE)
			.setBody(objectMapper.writeValueAsString(secretWords));
	}

	MockResponse createAuthServerGrantRequestSuccessResponse() {
		return new MockResponse().setResponseCode(200)
			.setBodyDelay(100, TimeUnit.MILLISECONDS)
			.setHeader(CONTENT_TYPE, APPLICATION_JSON_VALUE)
			.setBody(createTokenResponseBody());
	}

	MockResponse createResourceServerUnauthorizedResponse() {
		return new MockResponse().setResponseCode(401);
	}

	String createTokenResponseBody() {
		try {
			return objectMapper.writeValueAsString(createTokenResponse());
		}
		catch (JsonProcessingException e) {
			throw new RuntimeException("Failed to serialize token response", e);
		}
	}

	Map<String, Object> createTokenResponse() {
		// @formatter:off
		return Map.of(
				OAuth2ParameterNames.ACCESS_TOKEN, DUMMY_ACCESS_TOKEN,
				OAuth2ParameterNames.EXPIRES_IN, 3600,
				OAuth2ParameterNames.REFRESH_TOKEN, "dummy-refresh-token",
				OAuth2ParameterNames.TOKEN_TYPE, BEARER.getValue()
		);
		// @formatter:on
	}

	/*
	 * There must be a better way to do this.
	 * org.springframework.http.converter.FormHttpMessageConverter.writeForm does what we
	 * need but it is tightly coupled to an HttpOutputMessage
	 */
	String createTokenResponseAsFormData() {
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromPath("");
		createGrantRequestFormData().forEach(uriComponentsBuilder::queryParam);
		UriComponents build = uriComponentsBuilder.build();
		String s = build.toString();
		return s.substring(1); // Trim the leading '?' from the query params string
	}

	/*
	 * Reusing some of the code in Spring OAuth's
	 * DefaultClientCredentialsTokenResponseClient.getTokenResponse
	 */
	MultiValueMap<String, String> createGrantRequestFormData() {
		ClientRegistration myClientRegistration = clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID);
		var grantRequest = new OAuth2ClientCredentialsGrantRequest(myClientRegistration);
		return new DefaultOAuth2TokenRequestParametersConverter<OAuth2ClientCredentialsGrantRequest>()
			.convert(grantRequest);
	}

	@TestConfiguration
	static class TestConfig {

		@Bean
		Supplier<Instant> timestampSupplier() {
			return () -> FIXED_TIMESTAMP;
		}

		@Bean("oauth2RestClient")
		RestClient oauth2RestClient() {
			RestTemplate restTemplate = new RestTemplate(
					Arrays.asList(new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
			restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
			return RestClient.builder(restTemplate).build();
		}

		@Bean
		OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> tokenResponseClient(
				@Qualifier("oauth2RestClient") RestClient oauth2RestClient) {
			var defaultTokenResponseClient = new RestClientClientCredentialsTokenResponseClient();
			defaultTokenResponseClient.setRestClient(oauth2RestClient);
			return defaultTokenResponseClient;
		}

	}

}
