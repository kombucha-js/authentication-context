require('dotenv').config()
const { AuthenticationContext } = require('authentication-context' );
const { getAuthenticationSettingsAsync } = require('./authentication-context' );

beforeAll( ()=>{
  require('crypto-web-token/tokenizer.js' ).generateSalt();
});

test( 'login test', async ()=>{
  const settings = await getAuthenticationSettingsAsync();
  const context = AuthenticationContext.create().setOptions({reportResult:true,coloredReport:true});
  const res1 = await context.login({is_anonymous:true});

  const authentication_token = res1.value.token;
  console.log( authentication_token );

  const res12 = await context.set_user_identity( authentication_token );

  const res2 = await context.login({
    is_anonymous : false,
    username : settings.administrator.username,
    password : settings.administrator.password,
  });
  console.log( res2.value );
});

test( 'login test', async ()=>{
  const settings = await getAuthenticationSettingsAsync();
  const context = AuthenticationContext.create().setOptions({reportResult:true,coloredReport:true});
  const res1 = await context.login({is_anonymous:true});
  const authentication_token = res1.value.token;
  const res12 = await context.set_user_identity( authentication_token );
  const res2 = await context.login({
    is_anonymous : false,
    username : settings.administrator.username,
    password : settings.administrator.password,
  });
  console.log( res2.value );
});

