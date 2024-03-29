/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

public class BitlyAuthenticatorConstants {
    public static final String AUTHENTICATOR_NAME = "bitly";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "bitlyAuthenticator";

    //bitly authorize endpoint URL
    public static final String BITLY_OAUTH_ENDPOINT = "https://bitly.com/oauth/authorize";
    //bitly token  endpoint URL
    public static final String BITLY_TOKEN_ENDPOINT = "https://api-ssl.bitly.com/oauth/access_token";
    //bitly user info endpoint URL
    public static final String BITLY_USERINFO_ENDPOINT = "https://api-ssl.bitly.com/v4/user";
    public static final String ACCEPT_HEADER = "Accept";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String USER_DATA = "data";
    public static final String CALLBACK_URL = "callbackUrl";
    public static final String TOKEN_ENDPOINT = "tokenEndpoint";
    public static final String CODE = "code";
    public static final String GET_OAUTH_RESPONSE = "getOauthResponse";
    public static final String GET_SUBJECT_ATTRIBUTES = "getSubjectAttributes";
    public static final String GET_ACCESS_REQUEST = "getAccessRequest";
    public static final String APPLICATION_JSON_HEADER =  "application/json";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_HEADER = "Bearer";
    public static final String GET_METHOD = "GET";

}
