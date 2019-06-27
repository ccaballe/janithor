/*
 * Copyright (c) 2017. Stratio Big Data Inc., Sucursal en España. All rights reserved.
 *
 * This software – including all its source code – contains proprietary information of Stratio Big Data Inc., Sucursal
 * en España and may not be revealed, sold, transferred, modified, distributed or otherwise made available, licensed
 * or sublicensed to third parties; nor reverse engineered, disassembled or decompiled, without express written
 * authorization from Stratio Big Data Inc., Sucursal en España.
 */
package com.stratio.mesos.auth;

import com.stratio.mesos.http.CookieInterceptor;
import com.stratio.mesos.http.HTTPUtils;
import okhttp3.*;
import org.apache.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.util.StringJoiner;
import java.util.concurrent.TimeUnit;

public class SSOTokenResolver {
    final static Logger log = Logger.getLogger(SSOTokenResolver.class);

    private OkHttpClient.Builder clientBuilder;
    private OkHttpClient clientHttp;

    private String baseUrl;
    private String tenant;
    private String marathonUser;
    private String marathonSecret;
    private String token;

    private RedirectionInterceptor redirectionInterceptor;
    private CookieInterceptor cookieInterceptor;
    private long connectionTimeout = 30000;
    private long readTimeout = 30000;

    public SSOTokenResolver(String baseUrl, String user, String password) {
        this.baseUrl = baseUrl;
        this.marathonUser = user;
        this.marathonSecret = password;

        this.redirectionInterceptor = new RedirectionInterceptor();
        this.cookieInterceptor = new CookieInterceptor();
        this.clientBuilder = new OkHttpClient.Builder();
        this.clientBuilder = HTTPUtils.getUnsafeOkHttpClient();
        this.clientBuilder.addNetworkInterceptor(this.redirectionInterceptor);
        this.clientBuilder.addNetworkInterceptor(this.cookieInterceptor);
        this.clientBuilder.connectTimeout(connectionTimeout, TimeUnit.MILLISECONDS);
        this.clientBuilder.readTimeout(readTimeout, TimeUnit.MILLISECONDS);
        this.clientHttp = clientBuilder.build();

    }

    public SSOTokenResolver(String baseUrl, String user, String password, long connectionTimeout, long readTimeout) {
        this.baseUrl = baseUrl;
        this.marathonUser = user;
        this.marathonSecret = password;

        this.redirectionInterceptor = new RedirectionInterceptor();
        this.cookieInterceptor = new CookieInterceptor();
        this.clientBuilder = new OkHttpClient.Builder();
        this.clientBuilder = HTTPUtils.getUnsafeOkHttpClient();
        this.clientBuilder.addNetworkInterceptor(this.redirectionInterceptor);
        this.clientBuilder.addNetworkInterceptor(this.cookieInterceptor);
        this.clientBuilder.connectTimeout(connectionTimeout, TimeUnit.MILLISECONDS);
        this.clientBuilder.readTimeout(readTimeout, TimeUnit.MILLISECONDS);
        this.clientHttp = clientBuilder.build();
    }

    public SSOTokenResolver(String tenant, String baseUrl, String user, String password, long connectionTimeout, long readTimeout) {
        this.baseUrl = baseUrl;
        this.tenant = tenant;
        this.marathonUser = user;
        this.marathonSecret = password;

        this.redirectionInterceptor = new RedirectionInterceptor();
        this.cookieInterceptor = new CookieInterceptor();
        this.clientBuilder = new OkHttpClient.Builder();
        this.clientBuilder = HTTPUtils.getUnsafeOkHttpClient();
        this.clientBuilder.addNetworkInterceptor(this.redirectionInterceptor);
        this.clientBuilder.addNetworkInterceptor(this.cookieInterceptor);
        this.clientBuilder.connectTimeout(connectionTimeout, TimeUnit.MILLISECONDS);
        this.clientBuilder.readTimeout(readTimeout, TimeUnit.MILLISECONDS);
        this.clientHttp = clientBuilder.build();
    }


    public SSOTokenResolver(String tenant, String baseUrl, String user, String password) {
        this.baseUrl = baseUrl;
        this.tenant = tenant;
        this.marathonUser = user;
        this.marathonSecret = password;

        this.redirectionInterceptor = new RedirectionInterceptor();
        this.cookieInterceptor = new CookieInterceptor();
        this.clientBuilder = new OkHttpClient.Builder();
        this.clientBuilder = HTTPUtils.getUnsafeOkHttpClient();
        this.clientBuilder.addNetworkInterceptor(this.redirectionInterceptor);
        this.clientBuilder.addNetworkInterceptor(this.cookieInterceptor);
        this.clientBuilder.connectTimeout(connectionTimeout, TimeUnit.MILLISECONDS);
        this.clientBuilder.readTimeout(readTimeout, TimeUnit.MILLISECONDS);
        this.clientHttp = clientBuilder.build();
    }

    /**
     * Performs authentication and returns success or failure
     * @return true if token could be obtained, false otherwise
     */
    public boolean authenticate() {
        String[] bodyParams;
        StringJoiner joiner = new StringJoiner(";");

        log.debug("1. GO TO " + baseUrl);
        Response response1_1 = getRequest(baseUrl);
        log.debug(response1_1.toString());

        String callBackLocation = redirectionInterceptor.getLocationHistory().get(1);
        redirectionInterceptor.clearLocationHistory();

        log.debug("2. REDIRECT TO : " + callBackLocation);
        Response response1_2 = getRequest(callBackLocation);
        log.debug(response1_2.toString());

        String[] cookies = cookieInterceptor.getCookies().toArray(new String[cookieInterceptor.getCookies().size()]);
        for (String item : cookies) joiner.add(item);
        cookieInterceptor.clearCookies();
        log.debug("2. COOKIE : " + cookies);

        String callBackLocation2 = redirectionInterceptor.getLocationHistory().get(1);
        redirectionInterceptor.clearLocationHistory();

        log.debug("3. REDIRECT TO : " + callBackLocation2 + " with cookies");
        Response response1_3 = getRequest(callBackLocation2, joiner.toString());
        log.debug(response1_3.toString());

        try {
            bodyParams = parseBodyParams(response1_3.body().string());
        } catch (IOException e) {
            log.error("Unable to parse required body params to perform the authentication. Aborting", e);
            return false;
        }

        String lastRedirection = callBackLocation2;
        try {
            FormBody.Builder formBodyBuilder = new FormBody.Builder()
                    .add("lt", bodyParams[0]) // lt
                    .add("_eventId", bodyParams[2]) // event
                    .add("execution", bodyParams[1]) // execution
                    .add("submit", "LOGIN");
            if (this.tenant != null)
                formBodyBuilder.add("tenant", this.tenant);
                formBodyBuilder
                    .add("username", this.marathonUser)
                    .add("password", this.marathonSecret);
            FormBody formBody = formBodyBuilder.build();

            Request request = new Request.Builder()
                    .url(lastRedirection)
                    .addHeader("Cookie", joiner.toString())
                    .post(formBody)
                    .build();
            Response response2_1 = clientHttp.newCall(request).execute();
            log.debug(response2_1.toString());
        } catch (IOException e) {
            log.error("Unable to perform login. Aborting", e);
        }

        token = cookieInterceptor.getCookies().stream()
                .filter(c -> c.contains("dcos-acs-auth-cookie"))
                .map(c -> c.replace("dcos-acs-auth-cookie=", ""))
                .map(c -> c.split(";")[0])
                .findFirst()
                .orElse(null);
        log.debug("OAuth Token obtained: " + token);
        return token!=null && !token.isEmpty();
    }

    /**
     * Returns a ready to use dc/os token
     * @return
     */
    public String getToken() {
        return token;
    }

    /**
     * Extracts HTML parameters lt, execution and event required to perform SSO request
     * @param htmlDocument callback location content after sso redirection
     * @return {lt, execution, event}
     */
    private String[] parseBodyParams(String htmlDocument) {
        String[] bodyParams = new String[3]; // lt, execution, event
        org.jsoup.nodes.Document doc = Jsoup.parse(htmlDocument);
        Elements elements = doc.select("input[type=hidden]");
        for (Element element : elements){
            if (element.attr("name").equals("lt"))
                bodyParams[0] = element.attr("value");
            else if (element.attr("name").equals("execution"))
                bodyParams[1] = element.attr("value");
            else if (element.attr("name").equals("_eventId"))
                bodyParams[2] = element.attr("value");

        }
        return bodyParams;
    }

    /**
     * HTTP request execution based on url
     * @param url url to go to
     * @return Server response or null if error
     */
    private Response getRequest(String url) {
        return getRequest(url, null);
    }

    /**
     * HTTP request execution based on url
     * @param url url to go to
     * @param cookies to travel as a header
     * @return Server response or null if error
     */
    private Response getRequest(String url, String cookies) {
        Request request;
        try {
            if (cookies!=null) {
                request = new Request.Builder().addHeader("Cookie", cookies).url(url).build();
            } else {
                request = new Request.Builder().url(url).build();
            }
            return clientHttp.newCall(request).execute();
        } catch (IOException e) {
            log.error("Unable to get request for url " + url + " and cookies " + cookies, e);
            return null;
        }
    }
}



