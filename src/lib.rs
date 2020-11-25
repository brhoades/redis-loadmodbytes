#![allow(clippy::not_unsafe_ptr_arg_deref)]
pub(crate) mod context;

#[macro_use]
extern crate failure;
extern crate redis_module;

use std::fs::set_permissions;
use std::io::Write;
use std::os::raw::c_int;
use std::os::unix::fs::PermissionsExt;

use crate::context::*;
use failure::{format_err, Error};
use redis_module::{raw, Context as RContext, RedisError, RedisResult, RedisValue};
use tempfile::{Builder, NamedTempFile};

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

    match ctx.call("HGET", &[LOADED_MODULES_HASH_KEY, name.as_ref()])? {
        RedisValue::Null => (),
        _ => return Ok("ALREADY_LOADED".to_string()),
    };

    let bytes = base64::decode(module.as_ref())?;

    load_module_from_bytes(ctx, bytes, args)?;
    ctx.call(
        "HSET",
        &[LOADED_MODULES_HASH_KEY, name.as_ref(), module.as_ref()],
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
    if args.len() < 4 {
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

extern "C" fn do_command(
    ctx: *mut raw::RedisModuleCtx,
    argv: *mut *mut raw::RedisModuleString,
    argc: c_int,
) -> c_int {
    let context = RContext::new(ctx);

    // If chosen, replicate all commands to any replicas verbatim.
    // https://redis.io/topics/modules-api-ref#coderedismodulereplicatecode
    if unsafe { redis_module::raw::RedisModule_ReplicateVerbatim.unwrap()(ctx) }
        == redis_module::raw::Status::Err as c_int
    {
        return redis_module::raw::Status::Err as c_int;
    }

    if (argc as usize) < 2 {
        // not enough args
        return redis_module::raw::Status::Err as c_int;
    }

    /*
    let (bytes, args) = match unsafe { std::slice::from_raw_parts(argv, argc as usize) }.split_at(2)
    {
        ([_, bytes], args) => (bytes, args),
        (_, _) => return context.reply(Err(RedisError::WrongArity)) as c_int,
    };

    let bytes = unsafe {
        let mut len: libc::size_t = 0;
        let bytes = redis_module::raw::RedisModule_StringPtrLen.unwrap()(*bytes, &mut len);
        std::slice::from_raw_parts(bytes as *const u8, len)
    };
    */

    let args = unsafe { std::slice::from_raw_parts(argv, argc as usize) }
        .into_iter()
        .map(|&arg| {
            redis_module::RedisString::from_ptr(arg)
                .map(|v| v.to_owned())
                .map_err(|_| redis_module::RedisError::Str("UTF8 encoding error in handler args"))
        })
        .collect::<Result<Vec<String>, _>>();

    let response = args
        .map(|args| dispatch(&context, args))
        .unwrap_or_else(|e| Err(e));

    context.reply(response) as c_int
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn RedisModule_OnLoad(
    ctx: *mut redis_module::raw::RedisModuleCtx,
    _argv: *mut *mut redis_module::raw::RedisModuleString,
    _argc: std::os::raw::c_int,
) -> std::os::raw::c_int {
    use redis_module::raw;
    use std::ffi::CString;

    let context = RContext::new(ctx);
    // We use a statically sized buffer to avoid allocating.
    // This is needed since we use a custom allocator that relies on the Redis allocator,
    // which isn't yet ready at this point.
    let mut name_buffer = [0; 64];
    let commandname = "LOADMODBYTES";
    unsafe {
        std::ptr::copy(
            commandname.as_ptr(),
            name_buffer.as_mut_ptr(),
            "LOADMODBYTES".len(),
        );
    }

    let modulever = MODULE_VERSION as c_int;

    if unsafe {
        raw::Export_RedisModule_Init(
            ctx,
            name_buffer.as_ptr() as *const std::os::raw::c_char,
            modulever,
            raw::REDISMODULE_APIVER_1 as c_int,
        )
    } == raw::Status::Err as c_int
    {
        return raw::Status::Err as c_int;
    }

    if let Err(e) = initialize(ctx) {
        // context.MODULE_VERSIONwarning(format!("error initializing: {}", e).as_str());
        return raw::Status::Err as c_int;
    }

    // XXX: can pass module version to commmand now
    let name = CString::new(commandname).unwrap();
    let flags = CString::new("write").unwrap();
    if unsafe {
        raw::RedisModule_CreateCommand.unwrap()(
            ctx,
            name.as_ptr(),
            Some(do_command),
            flags.as_ptr(),
            0,
            0,
            0,
        )
    } == raw::Status::Err as c_int
    {
        return raw::Status::Err as c_int;
    }

    raw::Status::Ok as c_int
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn RedisModule_OnUnload(ctx: *mut redis_module::raw::RedisModuleCtx) -> c_int {
    let context = RContext::new(ctx);
    if deinitialize(&context) == redis_module::raw::Status::Err as c_int {
        return redis_module::raw::Status::Err as c_int;
    }

    redis_module::raw::Status::Ok as std::os::raw::c_int
}

const MODULE_VERSION: i32 = 2;
const LOADED_MODULES_LIST_KEY: &str = "LOADMODBYTES_MODULES_LIST";
const LOADED_MODULES_HASH_KEY: &str = "LOADMODBYTES_MODULES";
const LOADED_MODULES_KEY: &str = "LOADMODBYTES_MODULES";

// TODO: LRU
// Reads from LOADMODBYTES_MODULES and load all modules by their key.
fn initialize(ctx: *mut redis_module::raw::RedisModuleCtx) -> Result<(), failure::Error> {
    use redis_module::raw::*;

    if unsafe { subscribe_to_server_event(ctx, RedisModuleEvent_Loading, Some(load_callback)) }
        == Status::Ok
    {
        Ok(())
    } else {
        Err(format_err!("failed to register sever load event handler"))
    }
}

const AOF_START: u64 = redis_module::raw::REDISMODULE_SUBEVENT_LOADING_AOF_START;
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn load_callback(
    ctx: *mut redis_module::raw::RedisModuleCtx,
    eid: redis_module::raw::RedisModuleEvent,
    subevent: u64,
    _data: *mut ::std::os::raw::c_void,
) {
    let ctx = RContext::new(ctx);
    if subevent != redis_module::raw::REDISMODULE_SUBEVENT_LOADING_AOF_START {
        ctx.log_debug(
            format!(
                "load called with eid {:?} and subevent {}, but skipped as we want subevent {}",
                eid, subevent, AOF_START
            )
            .as_str(),
        );
        return;
    }

    match load_stored_modules(&ctx) {
        Err(e) => ctx.log_warning(&format!("errored on load module callback: {}", e)),
        _ => (),
    }
}

fn load_stored_modules(ctx: &RContext) -> Result<(), Error> {
    let modules = match ctx
        .call("HSCAN", &[LOADED_MODULES_KEY])
        .map_err(|e| format_err!("{}", e))?
    {
        RedisValue::Array(modules) => modules
            .into_iter()
            .filter_map(|m| match m {
                RedisValue::SimpleString(s) | RedisValue::BulkString(s) => Some(s),
                _ => None,
            })
            .scan(None, |last: &mut Option<String>, new| {
                if last.is_some() {
                    let name = last.clone();
                    *last = None;
                    Some((name.unwrap(), new))
                } else {
                    *last = Some(new);
                    None
                }
            })
            .collect::<Vec<_>>(),
        e => {
            return Err(format_err!(
                "returned unknown type for {}: {:?}",
                LOADED_MODULES_KEY,
                e
            ))?
        }
    };
    /*
    let key = ctx.open_key(LOADED_MODULES_LIST_KEY);
    let modules: Vec<String> = match key.get_value()? {
        Some(mods) => mods,
        None => {
            ctx.log_notice("no modules found to load");
            return Ok(());
        }
    };
    */

    if modules.len() > 0 {
        // ctx.log_notice(format!("there are {} module(s) to load", modules.len()).as_ref());
    }
    // ctx.log_notice(format!("modules: {:?}", modules).as_ref());

    /*
    for (name, bytes) in modules {
        ctx.log_notice(format!("loading module {}", name).as_ref());
        // XXX: support args
        load_module_from_bytes(ctx, bytes, vec![])?;
    }
    */
    // redis_module::raw::Status::Err as c_int
    Ok(())
}

fn deinitialize(ctx: &RContext) -> c_int {
    redis_module::raw::Status::Err as c_int
}
