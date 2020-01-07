/*
 *  Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.bitly;

import static org.mockito.Matchers.anyString;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import static org.mockito.MockitoAnnotations.initMocks;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

@RunWith(PowerMockRunner.class)
@PrepareForTest({OAuthAuthzResponse.class, OAuthClientRequest.class})
public class BitltTestClass2 {

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    private BitlyAuthenticator bitlyAuthenticator;
    @Mock
    private HttpServletRequest httpServletRequest;
    @Mock
    private HttpServletResponse httpServletResponse;
    @Mock
    private OAuthClientResponse oAuthClientResponse;
    @Mock
    private OAuthAuthzResponse authAuthzResponse;
    @Mock
    private OAuthClient oAuthClient;

    @Mock
    private OAuthClient mockOAuthClient;

    @Mock
    private OAuthClientRequest mockOAuthClientRequest;
    private OAuthJSONAccessTokenResponse oAuthJSONAccessTokenResponse = new OAuthJSONAccessTokenResponse();
    private Map<ClaimMapping, String> map = new HashMap<>();

    @Spy
    private AuthenticationContext context = new AuthenticationContext();

    @DataProvider
    public Object[][] getAuthenticatorPropertiesData() {
        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "test-client-id");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "test-client-secret");
        authenticatorProperties.put("callbackUrl", "http://localhost:9443/commonauth");
        return new Object[][]{{authenticatorProperties}};
    }

    @BeforeMethod
    public void setUp() {
        bitlyAuthenticator = new BitlyAuthenticator();
        initMocks(this);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class,
            description = "Negative Test case for processAuthenticationResponse",
            dataProvider = "getAuthenticatorPropertiesData")
    public void testProcessAuthenticationResponse(Map<String, String> authenticatorProperties) throws Exception {
        BitlyAuthenticator spyAuthenticator = PowerMockito.spy(new BitlyAuthenticator());
        PowerMockito.when(httpServletRequest.getParameter(anyString())).thenReturn("method");
        context.setAuthenticatorProperties(authenticatorProperties);
        PowerMockito.mockStatic(OAuthAuthzResponse.class);
        Mockito.when(OAuthAuthzResponse.oauthCodeAuthzResponse(Mockito.any(HttpServletRequest.class))).
                thenReturn(authAuthzResponse);
        PowerMockito.mockStatic(OAuthClientRequest.class);
        Mockito.when(OAuthClientRequest.tokenLocation(Mockito.anyString())).thenReturn(new OAuthClientRequest.
                TokenRequestBuilder("https://test-url"));
        PowerMockito.whenNew(OAuthClient.class).withAnyArguments().thenReturn(oAuthClient);
        Mockito.when(mockOAuthClient.accessToken(mockOAuthClientRequest)).thenReturn(oAuthJSONAccessTokenResponse);
        PowerMockito.when(oAuthClient.accessToken(Mockito.any(OAuthClientRequest.class))).
                thenReturn(oAuthJSONAccessTokenResponse);
        spyAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for getSubjectAttributes", dataProvider = "getAuthenticatorPropertiesData")
    public void testGetSubjectAttributes(Map<String, String> authenticatorProperties) throws Exception {
        Map<ClaimMapping, String> claims = Whitebox.invokeMethod(bitlyAuthenticator,
                "getSubjectAttributes", oAuthClientResponse,
                authenticatorProperties);
        Assert.assertEquals(0, claims.size());
    }
}
