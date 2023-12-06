//require('dotenv').config()
// MODIFIED (Wed, 27 Sep 2023 13:28:23 +0900)

import "./context.init.mjs";

import assert from 'node:assert/strict';
import { test, describe, it, before, after } from 'node:test';

import { AuthenticationContext }          from 'authentication-context' ;
import { getAuthenticationSettingsAsync } from 'authentication-context' ;
import { generateSalt }                   from 'crypto-web-token/tokenizer';

before( ()=>{
  console.error('before');
  generateSalt();
});

test( 'login test', async ()=>{
  const settings = await getAuthenticationSettingsAsync();
  console.log( {settings});
  const context = AuthenticationContext.create().setOptions({reportResult:true,coloredReport:true});
  try {
    const res1 = await context.login({is_anonymous:true});

    const authentication_token = res1.token;
    console.log( authentication_token );

    const res12 = await context.set_user_identity( authentication_token );

    const res2 = await context.login({
      is_anonymous : false,
      username : settings.administrator.username,
      password : settings.administrator.password,
    });
    console.log( res2 );
  } finally {
    context.logger.reportResult(true);
  }
});

test( 'login test', async ()=>{
  const settings = await getAuthenticationSettingsAsync();
  const context = AuthenticationContext.create().setOptions({reportResult:true,coloredReport:true});
  const res1 = await context.login({is_anonymous:true});
  const authentication_token = res1.token;
  const res12 = await context.set_user_identity( authentication_token );
  const res2 = await context.login({
    is_anonymous : false,
    username : settings.administrator.username,
    password : settings.administrator.password,
  });
  console.log( res2 );
});

