var clientInfo = {
    client_id : 'client id _ 80+MuQqthzU=',
    redirect_uri : 'https://localhost:44307/login-callback.html',
    scope : 'openid'
};

var providerInfo = OIDC.discover('https://identify2.safewhere.local/runtime/');
OIDC.setClientInfo( clientInfo );
OIDC.setProviderInfo( providerInfo );
OIDC.storeInfo(providerInfo, clientInfo);
// Remove State and Nonce from previous session
sessionStorage.removeItem('state');
sessionStorage.removeItem('nonce');
loginRequest = OIDC.generateLoginRequest({response_type : 'token id_token'});