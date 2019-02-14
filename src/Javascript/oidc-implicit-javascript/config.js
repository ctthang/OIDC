var clientInfo = {
    client_id : 'spa_clientid',
    redirect_uri : 'https://spa.safewhere.local/login-callback.html',
    scope : 'openid read write'
};

var providerInfo = OIDC.discover('https://develop.safewhere.local/runtime/');
OIDC.setClientInfo( clientInfo );
OIDC.setProviderInfo( providerInfo );
OIDC.storeInfo(providerInfo, clientInfo);
// Remove State and Nonce from previous session
sessionStorage.removeItem('state');
sessionStorage.removeItem('nonce');
loginRequest = OIDC.generateLoginRequest({response_type : 'token id_token'});