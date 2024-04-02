
import { schema }                               from  'vanilla-schema-validator' ;
import { preventUndefined }                     from  'prevent-undefined' ;
import { AsyncContext }                         from  'asynchronous-context/context' ;
import { encodeToken, decodeToken, TokenError } from  'crypto-web-token/tokenizer' ;
import { asyncReadSettings }                    from  'asynchronous-context/settings'  ;
import {
  LOGIN_USER_ID_SUPERUSER,
  LOGIN_USER_ID_ANONYMOUS,
  LOGIN_LEVEL_NONE,
  LOGIN_LEVEL_ANONYMOUS,
  LOGIN_LEVEL_USER,
  LOGIN_LEVEL_SUPERUSER } from  './header.mjs' ;

(await import( "./schema.mjs")).init( schema );

async function getAuthenticationSettingsAsync() {
  const json = ( preventUndefined( await asyncReadSettings(), schema.t_authentication_settings() ) ).authentication_context;

  // Ensure the administrator setting.
  if ((        json.administrator  instanceof  Object ) &&
      ( typeof json.administrator.username === 'string' ) &&
      ( typeof json.administrator.password === 'string' ))
  {
    json.administrator.activated = true;
  } else {
    // overrite it.
    json.administrator = {
      activated : false,
      username : null,
      password : null,
    };
  }

  return json;
}
export { getAuthenticationSettingsAsync };

class AuthenticationContext extends AsyncContext {
  constructor(...args) {
    super(...args);
  }
}
export { AuthenticationContext };

class AuthrozationError extends Error {
  constructor(...args) {
    super( ...args );
  }
}
export { AuthrozationError };


function calculate_valid_until(minutesToAdd = 30) {
  const currentDate  = new Date();
  const futureDate   = new Date( currentDate.getTime() + minutesToAdd * 60000 );
  return futureDate;
}

async function abstract_login({username,password}) {
  throw new AuthrozationError('not implemented');
  // return {
  //   login_level : LOGIN_LEVEL_USER,
  //   login_user_id: 'authorized-user',
  // };
}
// TAG_ABSTRACT_LOGIN (Wed, 14 Sep 2022 17:43:50 +0900)
AuthenticationContext.defineMethod( abstract_login );


// THE DEFINITION OF THE LOGIN PROCEDURE
async function login ( __nargs ) {
  const input = ( __nargs );
  const login_valid_until =  calculate_valid_until(30);

  let login_level;
  let login_user_id;

  // if ( ! ( 'username' in input ) ) {
  //   throw new ReferenceError( 'username is not specified' );
  // }

  //
  // 1. Check if it is an attempt of anonymous login.
  //
  if ( input.is_anonymous === true ) {
    login_level    = LOGIN_LEVEL_ANONYMOUS; // an anonymous user
    login_user_id  = LOGIN_USER_ID_ANONYMOUS;
    this.logger.log( 'login (anonymous) ' );
  } else {
    // this.logger.log( 'input.authentication_token', input.authentication_token );

    // TODO Clean this up (Wed, 07 Sep 2022 20:28:02 +0900)
    // /* `asynchronous-context-rpc/middleware.js` guarantees that `authentication_token` field always exists.
    //  * Therefore, this will not be executed. (Wed, 07 Sep 2022 16:56:20 +0900)
    //  * Whenever no authentication token is specified in the current HTTP header,
    //  * input.authentication_token is always null.
    //  */
    // if ( ! ( 'authentication_token' in input ) || input.authentication_token == null  ) {
    //   throw new ReferenceError( 'authentication token is not specified' );
    // }

    if ( ! ( 'username' in input ) || ( input.username == null )) {
      throw new ReferenceError( 'username is not specified' );
    }

    if ( ! ( 'password' in input ) || ( input.password == null )) {
      throw new ReferenceError( 'password is not specified' );
    }

    // this.logger.log( 'login (username) ', input.username );
    // this.logger.log( 'login (password) ', input.password );
    // this.logger.log( 'login (authentication_token) ', input.authentication_token );

    // TODO Clean this up (Wed, 07 Sep 2022 20:28:02 +0900)
    // const decoded_authentication_token = decodeToken( input.authentication_token );
    const decoded_authentication_token = (await this.get_user_identity());

    if ( decoded_authentication_token.login_level <  LOGIN_LEVEL_ANONYMOUS ) {
      throw new Error( 'the operation is not granted' );
    }

    this.logger.log( 'login (decoded) ', decoded_authentication_token );

    let suActivated = false;
    let suUsername = undefined;
    let suPassword = undefined;

    //
    // 2. Check the current superuser login setting.
    //
    try {
      const json = await getAuthenticationSettingsAsync();
      suActivated = json.administrator.activated;
      suUsername  = json.administrator.username;
      suPassword  = json.administrator.password;
    } catch (error){
      this.logger.error( {name: 'user.js', error });
      // intentionally ignore the contents of the error.
      // suActivated = false;
    }

    if ( suActivated ){
      this.logger.warn( 'WARNING: activated superuser setting' );
    } else {
      this.logger.warn( 'WARNING: ignored superuser setting' );
    }

    //
    // 3. Check if the login attempt is an attempt of superuser login.
    //
    if (  input.username === suUsername ) {
      // // an superuser login requires that the user has already been qualified as at least a general user.
      // if ( decoded_authentication_token.login_level < LOGIN_LEVEL_USER ) {
      //   throw new Error( 'the operation is not granted' );
      // }
      //
      if ( suActivated )  {
        if ( input.password === suPassword )  {
          // then, treat it as the superuser.
          login_level    = LOGIN_LEVEL_SUPERUSER; // the superuser
          login_user_id  = LOGIN_USER_ID_SUPERUSER;
          this.logger.log( 'superuser login succeeded' );
        } else {
          this.logger.warn( 'superuser login failed' );
          // If it detected an incorrect password;
          throw new AuthrozationError( 'incorrect password' );
        }
      } else {
          this.logger.warn( 'superuser login failed' );
        // If it detected an incorrect password; this is a possible attempt to
        // login as the superuser illegally.
        throw new AuthrozationError( 'incorrect password' );
      }
    } else {
      // TAG_ABSTRACT_LOGIN (Wed, 14 Sep 2022 17:43:50 +0900)
      const res = await this.abstract_login({username:input.username, password: input.password});
      login_level   = res.login_level;
      login_user_id = res.login_user_id;
    }
  }

  // MODIFIED (Wed, 19 Oct 2022 14:20:39 +0900)
  const current_user_id       = login_user_id;
  const current_user_id_stack = [ login_user_id ];
  const user_identity_token = {
    login_level,
    login_user_id,
    login_valid_until,
    current_user_id_stack,
    current_user_id, // MODIFIED (Wed, 19 Oct 2022 14:20:39 +0900)
  };

  this.logger.output({type:'identity-login', user_identity_token});

  const token = encodeToken( user_identity_token );

  return {token};
}
AuthenticationContext.defineMethod( login, 'POST',{
  typesafe_input  : schema.compile`array( object( is_anonymous: boolean() ) )`,
  typesafe_output : schema.compile`object( token:string() )`,
});

/*
 * login_status
 *
 * returns login status without querying to the database;
 */
async function login_status(nargs) {
  const user_identity_token = (await this.get_user_identity());
  return {
    login_level    : user_identity_token.login_level,
    login_user_id  : user_identity_token.login_user_id,
  };
}
AuthenticationContext.defineMethod( login_status, 'POST' );


/*
 * get_login_information()
 *
 * returns the current user's login-status and information from the database;
 */

async function abstract_login_information(nargs) {
  throw new AuthrozationError('not implemented');
}
AuthenticationContext.defineMethod( abstract_login_information, {
  typesafe_input : schema.compile`array( t_user_identity_token() )`,
  typesafe_output : schema.compile`t_user_login_info()`,
});


/*
 *
 */
async function get_login_information() {
  const user_identity_token = (await this.get_user_identity());
  const login_information   = (await this.abstract_login_information( user_identity_token ));
  return login_information;
}
AuthenticationContext.defineMethod( get_login_information, 'POST', {
  typesafe_input : schema.compile`array_of(any())`,
  typesafe_output : schema.compile`t_user_login_info()`,
});


async function abstract_switch_current_user({from_user_id,to_user_id}) {
  throw new AuthrozationError( 'not implemented' );
}
AuthenticationContext.defineMethod( abstract_switch_current_user );

async function switch_current_user({user_id}) {

  const prev_user_identity_token = (await this.get_user_identity());

  if ( prev_user_identity_token.current_user_id === user_id ) {
    return {accepted : false, token : null, };
  }

  const  allowed_switch_user = (await this.abstract_switch_current_user({user_id}));
  if ( allowed_switch_user ) {
    const new_user_identity_token = {
      login_level           :                prev_user_identity_token.login_level,
      login_user_id         :                prev_user_identity_token.login_user_id,
      login_valid_until     :                prev_user_identity_token.login_valid_until,
      current_user_id_stack : [ user_id, ... prev_user_identity_token.current_user_id_stack ],
      current_user_id       :   user_id, // <<< THE NEW VALUE
    };

    this.logger.log( { name: 'switch_current_user', comment: 'the result before encryption',  user_identity_token: new_user_identity_token } );


    const token = encodeToken( new_user_identity_token );
    const accepted = true;
    return {accepted,token};
  } else {
    // (Mon, 07 Nov 2022 18:55:47 +0900)
    throw new AuthrozationError('you are not allowed to switch to the specified user');
  }
}

AuthenticationContext.defineMethod( switch_current_user, 'POST', {
  typesafe_input  : schema.compile`array( object( user_id : t_user_id() ) )`,
  typesafe_output : schema.compile`t_switch_user_result()`,
});


async function switch_current_user_by_history({history_index}) {

  const prev_user_identity_token = (await this.get_user_identity());

  if ( 0<=history_index && history_index < prev_user_identity_token.current_user_id_stack.length ) {
    const new_user_identity_token  = ({
      login_level           :  prev_user_identity_token.login_level,
      login_user_id         :  prev_user_identity_token.login_user_id,
      login_valid_until     :  prev_user_identity_token.login_valid_until,
      current_user_id_stack :  prev_user_identity_token.current_user_id_stack.slice( history_index  ),
      current_user_id       :  prev_user_identity_token.current_user_id_stack      [ history_index  ], // <<< THE NEW VALUE
    });

    // this.logger.log({ history_index, prev_user_identity_token, new_user_identity_token });

    const token = encodeToken( new_user_identity_token );
    const accepted  = true;
    return { accepted , token };
  } else {
    throw new AuthrozationError('invalid history index error');
  }
}

AuthenticationContext.defineMethod( switch_current_user_by_history, 'POST', {
  typesafe_input  : schema.compile`array( object( history_index : number() ) )`,
  typesafe_output : schema.compile`t_switch_user_result()`,
});



//
// /**
//  *
//  * login_status({ token : 'TOKEN-VALUE' }) : ResultObject {
//  *    status : 'success' || 'error',
//  *    value : token || 'invalid'
//  * };
//  */
// async function login_status( nargs ) {
//   const input = ( nargs );
//   const decodedToken = ((token)=>{
//     try {
//       return decodeToken( token );
//     } catch ( e ) {
//       if ( e instanceof TokenError ) {
//         throw 'invalid';
//       } else {
//         // this.logger.log({pattern:2, input });
//         throw e;
//       }
//     }
//   })(input.token);
//
//   if ( new Date().getTime() < decodedToken.login_valid_until.getTime() ) {
//     // this.logger.log({pattern:3,input,decodedToken });
//     return decodedToken;
//   } else {
//     // throw 'expired';
//     throw 'invalid';
//   }
// }
// AuthenticationContext.defineMethod( login_status, 'POST' );


async function set_user_identity( __user_identity ) {
  if ( __user_identity == null ) {
    this.__user_identity = null;
  } else {
    this.__user_identity = decodeToken( __user_identity );
  }
  this.logger.output({type:'identity-current', value: this.__user_identity });
  return;
}
AuthenticationContext.defineMethod( set_user_identity );


async function get_user_identity() {
  let result = null;
  if ( this.__user_identity == null ) {
    result = {
      login_level           : LOGIN_LEVEL_NONE,
      login_user_id         : null,
      login_valid_until     : null,
      current_user_id_stack : [],
      current_user_id       : null,
    };
  } else {
    result = this.__user_identity;
  }
  this.logger.log({name:'get_user_identity',result});
  return result;
}

AuthenticationContext.defineMethod( get_user_identity, {
  // typesafe_input  : schema.compile`array( )`, // This throws an error. This should be fixed in vanilla-schema-validator.js
  typesafe_output : schema.compile`t_user_identity_token()`,
});



// NOT USED (Sat, 31 Dec 2022 12:04:04 +0900)
async function check_authentication({login_level, authentication_token}={}) {
  const decoded_authentication_token = decodeToken( input.authentication_token );
  if ( decoded_authentication_token.login_level <  login_level ) {
    return false;
  } else {
    return true;
  }
}
AuthenticationContext.defineMethod( check_authentication );


// NOT USED (Sat, 31 Dec 2022 12:04:04 +0900)
async function escalate_authentication( nargs ) {
  const login_level       = LOGIN_LEVEL_SUPERUSER; // the superuser
  const login_user_id     = LOGIN_USER_ID_SUPERUSER;
  const login_valid_until =  calculate_valid_until(30);
  const user_identity_token = {
    login_level,
    login_user_id,
    login_valid_until,
  };
  return encodeToken( user_identity_token );
}
AuthenticationContext.defineMethod( escalate_authentication );


