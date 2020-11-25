#![allow(clippy::not_unsafe_ptr_arg_deref)]
#[macro_use]
extern crate failure;
#[macro_use]
extern crate redis_module;

pub(crate) mod context;
pub(crate) mod hooks;

use std::fs::set_permissions;
use std::io::Write;
use std::os::{raw::c_int, unix::fs::PermissionsExt};

use failure::Error;
use redis_module::{raw, Context as RContext, RedisError, RedisResult, RedisValue};
use tempfile::{Builder, NamedTempFile};

use context::*;
use hooks::{deinitialize, initialize};

/// load_module takes the base64-encoded byte string, decodes it, writes it
/// to a temporary file, and then loads it into Redis. On success, it returns
/// a message that the call succeeded and the size of the module.
fn load_module<C: Context, N: AsRef<str>, M: AsRef<str>>(
    ctx: &C,
    name: N,
    module: M,
    args: Vec<String>,
) -> Result<String, Error> {
    ctx.replicate_verbatim();

    match ctx.call("HGET", &[crate::LOADED_MODULES_HASH_KEY, name.as_ref()])? {
        RedisValue::Null => (),
        _ => return Ok("ALREADY_LOADED".to_string()),
    };

    let bytes = base64::decode(module.as_ref())?;

    load_module_from_bytes(ctx, bytes, args)?;
    ctx.call(
        "HSET",
        &[
            crate::LOADED_MODULES_HASH_KEY,
            name.as_ref(),
            module.as_ref(),
        ],
    )
    .unwrap();
    Ok("SUCCESS".to_string())
}

fn load_module_from_bytes<C: Context, B: AsRef<[u8]>>(
    ctx: &C,
    bytes: B,
    args: Vec<String>,
) -> Result<(), Error> {
    let file = write_bytes_to_path(bytes.as_ref())?;

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
        .chain(args.iter().map(|s| s.as_str()))
        .collect::<Vec<_>>();

    ctx.call("MODULE", &loadargs)
        .map_err(|e| {
            format_err!(
                "failed on \"MODULE LOAD\" call:\n\t{}\n\nCould the module be corrupt or already loaded?",
                e
            )
        })?;
    Ok(())
}

/// dispatch wraps messages and errors returned from load_module into a redis-friendly
/// format.
fn dispatch(ctx: &RContext, mut args: Vec<String>) -> RedisResult {
    if args.len() < 3 {
        return Err(RedisError::WrongArity);
    }
    let modargs = args.split_off(3);
    let (name, b64) = match args.as_slice() {
        [_command_name, name, b64] => (name, b64),
        _ => return Err(RedisError::WrongArity),
    };

    load_module(ctx, name, &b64, modargs)
        .map(RedisValue::SimpleString)
        .map_err(|e| RedisError::String(format!("{}", e)))
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

const MODULE_VERSION: i32 = 2;
const LOADED_MODULES_LIST_KEY: &str = "LOADMODBYTES_MODULES_LIST";
const LOADED_MODULES_HASH_KEY: &str = "LOADMODBYTES_MODULES";

redis_module! {
    name: "loadmodbytes",
    version: MODULE_VERSION,
    data_types: [],
    init: initialize,
    deinit: deinitialize,
    commands: [
        ["LOADMODBYTES", dispatch, "write", 0, 0, 0],
    ],
}
