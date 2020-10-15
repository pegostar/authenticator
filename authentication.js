/*!
 * authentication v1.0.0
 *
 * Copyright 2020 Davide Pegoraro
 *
 * Date: 2020-10-12T11:10Z
 */
/* jshint node: true */
/*global Enumerator: false, ActiveXObject: false, Promise: false */
/**
 * The connector for the oauth2 server
 * @type {function(*=, *=, *=, *=, *=): {redirectUri: *, logout: function(): Promise, clientId: *, baseurl: *, renewRefreshToken: function(): Promise, clientsecret: *, detailUser: function(): any, accesstoken: string, realm: *, refreshtoken: string, loadPage: function(): void, login: function(string, string): Promise}}
 */
var OAuth2 = (function() {
    "use strict";

    /**
     * Represents a oauth2 connector.
     * @constructor
     * @param {string} realm - The name of the realm.
     * @param {string} clientid - The client identification.
     * @param {string} clientsecret - The client secret.
     * @param {string} baseurl - The url of the address authentication server.
     * @param {string} redirectUri - The redirect uri.
     */
    return function(realm, clientid, clientsecret, baseurl, redirectUri) {
        if (typeof new.target === "undefined") {
            throw new Error("Constructor must be called with new.");
        }

        /**
         * Decode the token jwt.
         * @param {string} token - The token in format jwt.
         * @return {object} The json object of the token.
         */
        function decodeToken (token) {
            var content = token.split('.')[1];

            content = content.replace('/-/g', '+');
            content = content.replace('/_/g', '/');
            switch (content.length % 4) {
                case 0:
                    break;
                case 2:
                    content += '==';
                    break;
                case 3:
                    content += '=';
                    break;
                default:
                    throw 'Invalid token';
            }

            content = (content + '===').slice(0, content.length + (content.length % 4));
            content = content.replace(/-/g, '+').replace(/_/g, '/');

            content = decodeURIComponent(window.escape(atob(content)));

            content = JSON.parse(content);
            return content;
        }

        /**
         * Recover the parameter in url by name.
         * @param {string} name - The name of the parameter.
         * @param {string} url - The url complete.
         * @return {string} The value of the parameter.
         */
        function getParameterByName(name, url) {
            if (!url) {
                url = window.location.href;
            }
            name = name.replace(/[\[\]]/g, '\\$&');
            var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
                results = regex.exec(url);
            if (!results) {
                return null;
            }
            if (!results[2]){
                return '';
            }
            return decodeURIComponent(results[2].replace(/\+/g, ' '));
        }

        /**
         * List of the endpoint.
         * @param {object} context - The current context of the function caller.
         * @return {string} The object witlh list url.
         */
        function endpoint(context) {
            var serverurl = context.baseurl;
            var realm = context.realm;
            var urlrealm = '';

            if (serverurl.charAt(serverurl.length - 1) === '/') {
                urlrealm = serverurl + 'realms/' + encodeURIComponent(realm);
            } else {
                urlrealm = serverurl + '/realms/' + encodeURIComponent(realm);
            }

            return {
                authorize: function() {
                    return urlrealm + '/protocol/openid-connect/auth';
                },
                token: function() {
                    return urlrealm + '/protocol/openid-connect/token';
                },
                logout: function() {
                    return urlrealm + '/protocol/openid-connect/logout';
                }
            };

        }

        /**
         * Perform creation uuid.
         * @return {string} The new uuid.
         */
        function createUUID() {
            var hexDigits = '0123456789abcdef';
            var item = generateRandomString(36, hexDigits).split("");
            item[14] = '4';
            item[19] = hexDigits.substr((item[19] & 0x3) | 0x8, 1);
            item[8] = item[13] = item[18] = item[23] = '-';

            return item.join('');
        }

        /**
         * Generate the random string
         * @param {int} len - The length of the random script
         * @param {string} alphabet - The list of alphabet.
         * @return {string} The new string.
         */
        function generateRandomString(len, alphabet){
            var randomData = generateRandomData(len);
            var chars = new Array(len);
            for (var i = 0; i < len; i++) {
                chars[i] = alphabet.charCodeAt(randomData[i] % alphabet.length);
            }
            return String.fromCharCode.apply(null, chars);
        }

        /**
         * Generate the random data.
         * @param {int} len - The length of the data.
         * @return {array} The new array
         */
        function generateRandomData(len) {
            // use web crypto APIs if possible
            var array = null;
            var crypto = window.crypto || window.msCrypto;
            if (crypto && crypto.getRandomValues && window.Uint8Array) {
                array = new Uint8Array(len);
                crypto.getRandomValues(array);
                return array;
            }

            // fallback to Math random
            array = new Array(len);
            for (var j = 0; j < array.length; j++) {
                array[j] = Math.floor(256 * Math.random());
            }
            return array;
        }

        /**
         * Get the new url of the login.
         * @param {object} context - The current context of the function caller.
         * @return {string} The url of form login keycloak
         */
        function createLoginUrl(context) {
            var state = createUUID();
            var nonce = createUUID();

            var callbackState = {
                state: state,
                nonce: nonce,
                redirectUri: encodeURIComponent(context.redirectUri)
            };

            var baseUrl = endpoint(context).authorize();

            var scope = "openid";

            var url = baseUrl;
            url += '?client_id=' + encodeURIComponent(context.clientId);
            url += '&redirect_uri=' + encodeURIComponent(context.redirectUri);
            url += '&state=' + encodeURIComponent(state);
            url += '&response_mode=' + encodeURIComponent("fragment");
            url += '&response_type=' + encodeURIComponent("code");
            url += '&scope=' + encodeURIComponent(scope);
            url = url + '&nonce=' + encodeURIComponent(nonce);

            LocalStorageExtend.add(callbackState);

            return url;
        }

        return {
            realm: realm,
            clientId: clientid,
            clientsecret: clientsecret,
            baseurl: baseurl,
            redirectUri: redirectUri,
            accesstoken: '',
            refreshtoken: '',
            /**
             * Perform load of the login page
             */
            loadPage: function () {
                var me = this;
                var path = '';
                if (window.location !== null) {
                    if (window.location.search !== null && window.location.search.length !== 0) {
                        path = window.location.search;
                    } else {
                        path = window.location.href;
                    }
                }

                if (path.indexOf("session_state") !== -1) {
                    var code = getParameterByName('code');
                    var url = endpoint(this).token();
                    var req = null;
                    try {
                        req = window.XMLHttpRequest?new XMLHttpRequest(): new ActiveXObject("Microsoft.XMLHTTP");
                    } catch (e) {
                        console.error("Error in creation XMLHttpRequest");
                    }

                    if(req !== null) {
                        req.open('POST', url, true);
                        req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                        var params = 'code=' + code + '&grant_type=authorization_code';
                        params += '&client_id=' + encodeURIComponent(this.clientId);
                        params += '&client_secret=' + encodeURIComponent(this.clientsecret);
                        params += '&redirect_uri=' + encodeURIComponent(this.redirectUri);

                        req.withCredentials = true;

                        req.onreadystatechange = function() {

                            if (req.readyState === XMLHttpRequest.DONE) {
                                if (req.status === 200) {
                                    var tokenResponse = JSON.parse(req.responseText);
                                    me.accesstoken = tokenResponse.access_token;
                                    me.refreshtoken = tokenResponse.refresh_token;
                                }
                            }
                        };

                        req.send(params);
                    }
                } else {
                    var urlLogin = createLoginUrl(this);
                    window.location.replace(urlLogin);
                }
            },
            /**
             * Fetch action login get the token for the communication.
             * @param {string} username - The username.
             * @param {string} password - The password.
             * @return {Promise} The object promise.
             */
            login: function(username, password) {
                var me = this;
                return new Promise(function(resolve, reject) {
                    var url = endpoint(me).token();
                    var req = null;
                    try {
                        req = window.XMLHttpRequest?new XMLHttpRequest(): new ActiveXObject("Microsoft.XMLHTTP");
                    } catch (e) {
                        console.error("Error in creation XMLHttpRequest");
                        reject(new Error("Error in creation XMLHttpRequest"));
                    }

                    if(req !== null) {
                        req.open('POST', url, true);
                        req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

                        var params = 'client_id=' + encodeURIComponent(me.clientId);
                        params += '&client_secret=' + encodeURIComponent(me.clientsecret);
                        params += '&username=' + encodeURIComponent(username);
                        params += '&password=' + encodeURIComponent(password);
                        params += '&grant_type=password';


                        req.withCredentials = false;

                        req.onreadystatechange = function() {
                            if (req.readyState === XMLHttpRequest.DONE) {
                                if (req.status === 200) {
                                    var tokenResponse = JSON.parse(req.responseText);
                                    me.accesstoken = tokenResponse.access_token;
                                    me.refreshtoken = tokenResponse.refresh_token;

                                    resolve({
                                        accesstoken: me.accesstoken,
                                        refreshtoken: me.refreshtoken
                                    });
                                } else {
                                    reject(new Error("Error token not present"));
                                }
                            }
                        };

                        req.send(params);
                    }
                });
            },
            /**
             * Get object json to the decrypted token.
             * @return {object} The object json.
             */
            detailUser: function () {
                return decodeToken(this.accesstoken);
            },
            /**
             * Fetch action renew token.
             * @return {Promise} The object promise.
             */
            renewRefreshToken: function() {
                var me = this;
                return new Promise(function(resolve, reject) {
                    var url = endpoint(me).token();

                    var req = null;
                    try {
                        req = window.XMLHttpRequest?new XMLHttpRequest(): new ActiveXObject("Microsoft.XMLHTTP");
                    } catch (e) {
                        console.error("Error in creation XMLHttpRequest");
                        reject(new Error("Error in creation XMLHttpRequest"));
                    }

                    if(req !== null) {
                        req.open('POST', url);
                        req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

                        var params = 'client_id=' + encodeURIComponent(me.clientId);
                        params += '&client_secret=' + encodeURIComponent(me.clientsecret);
                        params += '&refresh_token=' + encodeURIComponent(me.refreshtoken);
                        params += '&grant_type=refresh_token';

                        req.withCredentials = false;

                        req.onreadystatechange = function() {
                            if (req.readyState === XMLHttpRequest.DONE) {
                                if (req.status >= 200 && req.status < 300) {
                                    var tokenResponse = JSON.parse(req.responseText);
                                    me.accesstoken = tokenResponse.access_token;
                                    me.refreshtoken = tokenResponse.refresh_token;

                                    resolve({
                                        accesstoken: me.accesstoken,
                                        refreshtoken: me.refreshtoken
                                    });
                                } else {
                                    reject(new Error("Error token not present"));
                                }
                            }
                        };

                        req.send(params);
                    }
                });
            },

            /**
             * Fetch action logout token.
             * @return {Promise} The object promise.
             */
            logout: function() {
                var me = this;
                return new Promise(function(resolve, reject) {
                    var url = endpoint(me).logout();

                    var req = null;
                    try {
                        req = window.XMLHttpRequest?new XMLHttpRequest(): new ActiveXObject("Microsoft.XMLHTTP");
                    } catch (e) {
                        console.error("Error in creation XMLHttpRequest");
                        reject(new Error("Error in creation XMLHttpRequest"));
                    }

                    if(req !== null) {
                        req.open('POST', url);
                        req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

                        var params = 'client_id=' + encodeURIComponent(me.clientId);
                        params += '&client_secret=' + encodeURIComponent(me.clientsecret);
                        params += '&refresh_token=' + encodeURIComponent(me.refreshtoken);

                        req.withCredentials = false;

                        req.onreadystatechange = function() {
                            if (req.readyState === XMLHttpRequest.DONE) {
                                if (req.status >= 200 && req.status < 300) {
                                    me.accesstoken = '';
                                    me.refreshtoken = '';
                                    LocalStorageExtend.clearExpired();
                                    resolve(true);
                                } else {
                                    reject(new Error("Invalid logout"));
                                }
                            }
                        };

                        req.send(params);
                    }
                });
            }
        };
    };
}());

/**
 * The object localstorage for communication keycloak
 * @type {{add: LocalStorageExtend.add, clearExpired: LocalStorageExtend.clearExpired, get: (function(string): string)}}
 */
var LocalStorageExtend = (function() {
    "use strict";
    localStorage.setItem('kc-test', 'test');
    localStorage.removeItem('kc-test');

    return {
        /**
         * Clear key
         */
        clearExpired: function() {
            var time = new Date().getTime();
            for (var i = 0; i < localStorage.length; i++)  {
                var key = localStorage.key(i);
                if (key && key.indexOf('kc-callback-') === 0) {
                    var value = localStorage.getItem(key);
                    if (value) {
                        try {
                            var expires = JSON.parse(value).expires;
                            if (!expires || expires < time) {
                                localStorage.removeItem(key);
                            }
                        } catch (err) {
                            localStorage.removeItem(key);
                        }
                    }
                }
            }
        },
        /**
         * Get the value key.
         * @param {string} state - The key.
         * @return {string} The value of the key.
         */
        get: function(state) {
            if (!state) {
                return;
            }

            var key = 'kc-callback-' + state;
            var value = localStorage.getItem(key);
            if (value) {
                localStorage.removeItem(key);
                value = JSON.parse(value);
            }

            this.clearExpired();
            return value;
        },
        /**
         * Set the value of the key.
         * @param {string} state - The value.
         */
        add: function(state) {
            this.clearExpired();

            var key = 'kc-callback-' + state.state;
            state.expires = new Date().getTime() + (60 * 60 * 1000);
            localStorage.setItem(key, JSON.stringify(state));
        }
    };
}());