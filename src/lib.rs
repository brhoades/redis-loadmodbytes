pub mod errors;

#[macro_use]
extern crate redis_module;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use failure::format_err;
use redis_module::{Context, RedisError, RedisResult, RedisValue};
use tempfile::Builder;

use errors::*;

/// load_module takes the base64-encoded byte string, decodes it, writes it
/// to a temporary file, and loads it into Redis. On success, it returns
/// a message that the call succeeded and the byte count.
fn load_module(ctx: &Context, args: Vec<String>) -> Result<String, Error> {
    if args.len() != 2 {
        return Err(Error::wrong_arity());
    }

    let bytes = args.get(1).ok_or(Error::wrong_arity())?;
    let bytes = base64::decode(bytes)?;
    let size = bytes.len();

    let mut file = Builder::new()
        .prefix("redis-loadmodbytes-")
        .suffix(".so")
        .rand_bytes(5)
        .tempfile()?;
    file.write(&bytes)?;

    let (_, path) = file.keep()?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;

    let pathstr = path.to_str().unwrap();

    ctx.call("MODULE", &["LOAD", pathstr])
        .map(|_| Ok(format!("successfully loaded {} byte module", size)))
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

redis_module! {
    name: "LOADMODBYTES",
    version: 1,
    data_types: [],
    commands: [
        ["LOADMODBYTES", dispatch, "", 0, 0, 0],
    ],
}
