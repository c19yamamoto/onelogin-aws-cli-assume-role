package com.onelogin.aws.assume.role.cli;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.Request;
import com.microsoft.playwright.Route;
import com.microsoft.playwright.TimeoutError;
import com.microsoft.playwright.options.WaitUntilState;

/**
 * Signs in through OneLogin's hosted app launch page and captures the SAML POST
 * intended for AWS. The OneLogin login and MFA policy are completed by the user
 * in the visible browser.
 */
final class BrowserSamlAuthenticator {

	private static final double AUTHENTICATION_TIMEOUT_MILLIS = 10 * 60 * 1000;
	private static final String COMPLETION_PAGE = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in complete</title></head>"
			+ "<body><p>OneLogin sign-in complete. Return to the terminal.</p></body></html>";

	private BrowserSamlAuthenticator() {
	}

	static String getSamlResponse(String appId, String oneloginSubdomain, String browserChannel) throws Exception {
		String launchUrl = buildLaunchUrl(appId, oneloginSubdomain);
		try (Playwright playwright = Playwright.create()) {
			BrowserType.LaunchOptions launchOptions = new BrowserType.LaunchOptions().setHeadless(false);
			if (browserChannel != null && !"chromium".equals(browserChannel)) {
				launchOptions.setChannel(browserChannel);
			}
			Browser browser = playwright.chromium().launch(launchOptions);
			try {
				BrowserContext context = browser.newContext();
				try {
					Page page = context.newPage();
					final String[] samlResponse = new String[1];
					final Exception[] captureError = new Exception[1];

					context.route("**/saml**", route -> handleRoute(route, samlResponse, captureError));

					System.out.println("Opening OneLogin in a browser. Complete sign-in and MFA there.");
					Request request;
					try {
						request = page.waitForRequest(BrowserSamlAuthenticator::isAwsSamlPost,
								new Page.WaitForRequestOptions().setTimeout(AUTHENTICATION_TIMEOUT_MILLIS),
								() -> page.navigate(launchUrl,
										new Page.NavigateOptions().setWaitUntil(WaitUntilState.DOMCONTENTLOADED)));
					} catch (TimeoutError e) {
						if (captureError[0] != null) {
							throw captureError[0];
						}
						throw new Exception("Timed out waiting for OneLogin browser authentication to finish.", e);
					}

					if (captureError[0] != null) {
						throw captureError[0];
					}
					if (samlResponse[0] == null) {
						samlResponse[0] = extractSamlResponse(request.postData());
					}
					System.out.println("OneLogin browser authentication complete.");
					return samlResponse[0];
				} finally {
					context.close();
				}
			} finally {
				browser.close();
			}
		}
	}

	private static String buildLaunchUrl(String appId, String subdomain) {
		if (appId == null || !appId.matches("[0-9]+")) {
			throw new IllegalArgumentException("OneLogin App ID must contain only digits.");
		}
		if (subdomain == null || !subdomain.matches("[A-Za-z0-9-]+")) {
			throw new IllegalArgumentException("OneLogin subdomain must contain only letters, digits, and hyphens.");
		}
		return "https://" + subdomain + ".onelogin.com/launch/" + appId;
	}

	private static void handleRoute(Route route, String[] samlResponse, Exception[] captureError) {
		Request request = route.request();
		if (!isAwsSamlPost(request)) {
			route.resume();
			return;
		}

		try {
			samlResponse[0] = extractSamlResponse(request.postData());
			route.fulfill(new Route.FulfillOptions().setStatus(200)
					.setContentType("text/html; charset=utf-8").setBody(COMPLETION_PAGE));
		} catch (Exception e) {
			captureError[0] = e;
			route.abort();
		}
	}

	private static boolean isAwsSamlPost(Request request) {
		if (!"POST".equalsIgnoreCase(request.method())) {
			return false;
		}
		try {
			URI uri = URI.create(request.url());
			if (!"https".equalsIgnoreCase(uri.getScheme()) || !"/saml".equals(uri.getPath())) {
				return false;
			}
			String host = uri.getHost();
			if (host == null) {
				return false;
			}
			host = host.toLowerCase(Locale.ROOT);
			return isHostOrSubdomain(host, "signin.aws.amazon.com")
					|| isHostOrSubdomain(host, "signin.amazonaws-us-gov.com")
					|| isHostOrSubdomain(host, "signin.amazonaws.cn");
		} catch (IllegalArgumentException e) {
			return false;
		}
	}

	private static boolean isHostOrSubdomain(String host, String allowedHost) {
		return host.equals(allowedHost) || host.endsWith("." + allowedHost);
	}

	private static String extractSamlResponse(String postData) throws Exception {
		if (postData == null || postData.isEmpty()) {
			throw new Exception("AWS sign-in request did not contain a form body.");
		}
		List<NameValuePair> form = URLEncodedUtils.parse(postData, StandardCharsets.UTF_8);
		String samlResponse = null;
		for (NameValuePair parameter : form) {
			if ("SAMLResponse".equals(parameter.getName())) {
				if (samlResponse != null) {
					throw new Exception("AWS sign-in request contained multiple SAMLResponse values.");
				}
				samlResponse = parameter.getValue();
			}
		}
		if (samlResponse == null || samlResponse.trim().isEmpty()) {
			throw new Exception("AWS sign-in request did not contain a SAMLResponse.");
		}
		return samlResponse;
	}
}
