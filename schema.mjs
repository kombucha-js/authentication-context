

const symbol = Symbol.for('authentication-context');

function init( schema ) {
  if ( symbol in schema ) {
    return schema;
  }
  Object.defineProperty( schema, symbol, {
    value : true,
    enumerable : true,
  });

  schema.t_args = schema.compile`array()`;

  schema.t_user_id = schema.compile`
    or(
      null(),
      equals(<< 'superuser' >>),
      equals(<< 'anonymous' >>),
      equals(<< 'yourself'  >>),
      uuid(),
    )`

  schema.t_username = schema.compile`
    or(
      null(),
      string(),
      any(),
    )
  `;

  schema.t_user_identity_token = schema.compile`
    object(
      login_level           : number(),
      login_user_id         : t_user_id(),
      login_valid_until     : any(),
      current_user_id       : t_user_id(),
      current_user_id_stack : array_of( t_user_id() ),
    )
  `;

  schema.t_user_login_info = schema.compile`
    object(
      login_level            : number(),
      login_user_id          : t_user_id(),
      login_username         : t_username(),
      login_valid_until      : any(),
      current_user_id_stack  : array_of( t_user_id() ),
      current_user_id        : t_user_id(),
      current_username_stack : array_of( t_username() ),
      current_username       : t_username(),
    )
  `;
  schema.t_encrypted_token = schema.compile`string()`;

  schema.t_switch_user_result = schema.compile`
    object(
      accepted : boolean(),
      token :  or( t_encrypted_token(), null() ),
    )
  `;

  schema.t_authentication_settings = schema.compile`
    object(
      authentication_context : object(
        administrator : or(
          object(
            username : string(),
            password : string(),
          ),
          null(),
        ),
      ),
    ),
  `;
  return schema;
}

export { init };
