use std::os::raw::c_int;

use failure::Error;
use redis_module::{raw, Context as RContext, RedisValue};

use crate::{context::*, LOADED_MODULES_HASH_KEY};

const AOF_START: u64 = redis_module::raw::REDISMODULE_SUBEVENT_LOADING_AOF_START;
const MODULE_UNLOADED: u64 = redis_module::raw::REDISMODULE_SUBEVENT_MODULE_UNLOADED;

// TODO: LRU
// Reads from LOADMODBYTES_MODULES and load all modules by their key.
pub fn initialize(ctx: *mut raw::RedisModuleCtx) -> c_int {
    let context = RContext::new(ctx);
    let hook_load_results = unsafe {
        vec![
            (
                "before AOF load",
                raw::subscribe_to_server_event(
                    ctx,
                    raw::RedisModuleEvent_Loading,
                    Some(load_stored_modules_callback),
                ),
            ),
            (
                "module unload",
                raw::subscribe_to_server_event(
                    ctx,
                    raw::RedisModuleEvent_ModuleChange,
                    Some(unload_module_callback),
                ),
            ),
        ]
    };

    for (name, res) in hook_load_results {
        if res != raw::Status::Ok {
            context.log_warning(&format!("failed to register {} event handler", name));
            return res as c_int;
        }
    }

    raw::Status::Ok as c_int
}

pub fn deinitialize(_ctx: *mut raw::RedisModuleCtx) -> c_int {
    raw::Status::Ok as c_int
}

#[no_mangle]
pub extern "C" fn load_stored_modules_callback(
    ctx: *mut redis_module::raw::RedisModuleCtx,
    eid: redis_module::raw::RedisModuleEvent,
    subevent: u64,
    _data: *mut ::std::os::raw::c_void,
) {
    let ctx = RContext::new(ctx);
    ctx.log_debug(&format!(
        "load callback with {:?} and subevent {} received",
        eid, subevent
    ));
    if subevent != AOF_START {
        ctx.log_debug(&format!(
            "skipping callback as we want subevent {}",
            AOF_START
        ));
        return;
    } else {
        ctx.log_notice("beginning load callback before AOF");
    }

    match load_stored_modules(&ctx) {
        Err(e) => ctx.log_warning(&format!("errored on load module callback: {}", e)),
        _ => (),
    }
}

fn load_stored_modules<C: Context>(ctx: &C) -> Result<(), Error> {
    let modules = match ctx.call("HSCAN", &[LOADED_MODULES_HASH_KEY, "0"])? {
        RedisValue::Array(cursor_modules) => cursor_modules,
        e => {
            return Err(format_err!(
                "returned unknown type for {}: {:?}",
                LOADED_MODULES_HASH_KEY,
                e
            ))
        }
    };
    let modules = modules
        .into_iter()
        .skip(1)
        .map(|m| match m {
            RedisValue::Null => Ok(vec![]),
            RedisValue::Array(values) => Ok(values),
            other => Err(format_err!("unknown type from HSCAN: {:?}", other)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let modules = modules
        .first()
        .ok_or_else(|| format_err!("no result returned from HSCAN {}", LOADED_MODULES_HASH_KEY))?;

    if modules.len() == 0 {
        ctx.log_debug("no modules found to load");
        return Ok(());
    }

    let modules = modules
        .into_iter()
        .filter_map(|m| match m {
            RedisValue::SimpleString(s) | RedisValue::BulkString(s) => Some(s),
            _ => None,
        })
        .scan(None, |last: &mut Option<&String>, new| {
            if last.is_some() {
                let name = last.clone();
                *last = None;
                Some((name.unwrap(), new))
            } else {
                *last = Some(new);
                None
            }
        })
        .collect::<Vec<_>>();

    ctx.log_notice(format!("there are {} module(s) to load", modules.len()));
    for (name, bytes) in modules {
        ctx.log_notice(format!("loading module {}", name));
        // XXX: support args
        crate::load_module_from_bytes(ctx, bytes, vec![])?;
    }

    Ok(())
}

// unload_module_callback does bookkeeping to remove modules manually unloaded by users.
#[no_mangle]
pub extern "C" fn unload_module_callback(
    context: *mut redis_module::raw::RedisModuleCtx,
    eid: redis_module::raw::RedisModuleEvent,
    subevent: u64,
    data: *mut ::std::os::raw::c_void,
) {
    let ctx = RContext::new(context);
    if subevent != MODULE_UNLOADED {
        ctx.log_debug(&format!(
            "module changed with eid {:?} and subevent {}, but skipped as we want subevent {}",
            eid, subevent, MODULE_UNLOADED,
        ));
        return;
    }

    if data.is_null() {
        ctx.log_warning("module change called with null data pointer");
        return;
    }
    let data = unsafe { data as *mut raw::RedisModuleModuleChange };
    let data = unsafe { &*data };
    let name = match unsafe { std::ffi::CStr::from_ptr(data.module_name).to_str() } {
        Ok(s) => s,
        Err(e) => {
            ctx.log_warning(&format!(
                "unable to parse module name string from {:?}: {}",
                data, e
            ));
            return;
        }
    };

    if let Err(e) = record_module_unloaded(&ctx, name) {
        ctx.log_warning(&format!(
            "errored on load module callback ({:?}): {}",
            data, e
        ));
    }
}

fn record_module_unloaded<C: Context, T: AsRef<str>>(ctx: &C, name: T) -> Result<(), Error> {
    let name = name.as_ref();
    let unloaded = match ctx.call("HDEL", &[LOADED_MODULES_HASH_KEY, name])? {
        RedisValue::Integer(0) => false,
        RedisValue::Integer(_) => true,
        other => {
            return Err(format_err!(
                "unknown response from HDEL {}: {:?}",
                LOADED_MODULES_HASH_KEY,
                other
            ))
        }
    };

    Ok(())
}
