## Description

The authenticator library allows you to login to an Oauth2 server, without using the keycloak javascript adapters and without the server side adapters.

The library, unlike the adapter, allows easier integration with the chosen frontend framework and does not need the json containing the client id and client secret.

The same used in a project can be minimized and obfuscated with online tools.

It essentially consists of:



**loadPage**: If inserted in the load of an html page it allows if the token is not present to automatically redirect to the login page

`var oauth = new OAuth2("myrealname", "myclientid","becc2062-602d-414a-bebd-dc55e1dfda69", "urlserveroauth2", "urlmywebapplication");`
        `window.onload = function() {`
            `oauth.loadPage();`
        `};`



**login**: Allows you to login using an application page and manage the login phase

`var oauth = new OAuth2("myrealname", "myclientid","becc2062-602d-414a-bebd-dc55e1dfda69", "urlserveroauth2", "urlmywebapplication");`
`function login() {`
            `oauth.login("pegostar", "password")..then((result) => {`
                        `})`
                        `.catch((err) => {`

​                       `});`

​        `}`



**detailUser**: Returns a json object that desbuses the token, such as jwt.io

**renewRefreshToken**: Renew the access token because it has expired

**logout**: Allow logout operation, invalidating tokens and cleaning system objects for keycloak


