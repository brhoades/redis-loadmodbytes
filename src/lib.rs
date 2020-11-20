#![allow(clippy::not_unsafe_ptr_arg_deref)]
pub mod errors;
#[macro_use]
extern crate redis_module;

use std::fs::set_permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use failure::format_err;
use redis_module::{Context, RedisError, RedisResult, RedisValue};
use tempfile::{Builder, NamedTempFile};

use errors::*;

/// load_module takes the base64-encoded byte string, decodes it, writes it
/// to a temporary file, and then loads it into Redis. On success, it returns
/// a message that the call succeeded and the size of the module.
fn load_module(ctx: &Context, args: Vec<String>) -> Result<String, Error> {
    if args.len() < 2 {
        return Err(Error::wrong_arity());
    }

    let (mut bytes, modargs): (Vec<(usize, _)>, _) = args
        .into_iter()
        .skip(1)
        .enumerate()
        .partition(|(i, _)| *i == 0);
    let bytes = bytes.pop().ok_or_else(Error::wrong_arity)?.1;
    let modargs = modargs.into_iter().map(|(_, e)| e).collect::<Vec<_>>();

    let bytes = base64::decode(bytes)?;
    let file = write_bytes_to_path(&bytes)?;

    // This error case should never happen since we control the temp file name, right?
    // Just handling it instead of a redis-crashing panic.
    let pathstr = file.path().to_str().ok_or_else(|| {
        format_err!(
            "failed to convert temp module \"{:?}\" unicode string",
            file.path().as_os_str()
        )
    })?;
    let loadargs = vec!["LOAD", pathstr]
        .into_iter()
        .chain(modargs.iter().map(String::as_str))
        .collect::<Vec<_>>();

    ctx.call("MODULE", &loadargs)
        .map(|_| Ok("SUCCESS".to_string()))
        .map_err(|e| {
            format_err!(
                "failed on \"MODULE LOAD\" call:\n\t{}\n\nCould the module be corrupt or already loaded?",
                e
            )
        })?
}

/// dispatch wraps messages and errors returned from load_module into a redis-friendly
/// format.
fn dispatch(ctx: &Context, args: Vec<String>) -> RedisResult {
    load_module(ctx, args)
        .map(RedisValue::SimpleString)
        .map_err(RedisError::from)
}

fn write_bytes_to_path(bytes: &[u8]) -> Result<NamedTempFile, Error> {
    let mut file = Builder::new()
        .prefix("redis-loadmodbytes-")
        .suffix(".so")
        .rand_bytes(5)
        .tempfile()?;
    file.write_all(&bytes)?;

    // redis expects +x
    set_permissions(file.path(), std::fs::Permissions::from_mode(0o755))?;
    Ok(file)
}

redis_module! {
    name: "LOADMODBYTES",
    version: 2,
    data_types: [],
    commands: [
        ["LOADMODBYTES", dispatch, "", 0, 0, 0, true],
    ],
}
