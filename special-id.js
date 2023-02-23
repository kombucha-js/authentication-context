
function get_special_id( id ) {
  return 'F#@*'+ id + '*@#F';
}
function is_special_id(id) {
  return id.substring(0,4) === 'F#@*' && id.substring( id.length-4 ) === '*@#F';
}
function strip_special_id( id ) {
  if ( is_special_id( id ) ) {
    id = id.substring(4);
    id = id.substring(0, id.length-4);
    return id;
  } else {
    return null;
  }
}

function check_special_user_id( user_id ) {
  if (user_id === LOGIN_USER_ID_ANONYMOUS ) {
    return get_special_id( LOGIN_USER_ID_ANONYMOUS );
  } else if (user_id === LOGIN_USER_ID_SUPERUSER ) {
    return get_special_id( LOGIN_USER_ID_SUPERUSER );
  } else {
    return null;
  }
}
