#[macro_use]
extern crate redis_module;
#[macro_use]
extern crate dlopen_derive;

use dlopen::wrapper::{Container, WrapperApi};
use failure::{format_err, Error as FailError};
use std::io::{self, Write};
use tempfile::Builder;

use redis_module::{Context, RedisError, RedisResult, RedisValue};

#[derive(WrapperApi)]
struct Module<'a> {
    #[dlopen_name = "mod_name"]
    name: fn() -> &'static str,
    #[dlopen_name = "mod_version"]
    version: fn() -> u32,

    // NB: function calls can cause panics which will kill redis. This symbol
    // will be looked up on load and, if absent, we'll catch it and error
    // the load call.
    is_mod: &'a bool,
}

enum Error {
    Redis(RedisError),
    Other(FailError),
}

impl From<Error> for RedisError {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            Redis(e) => e,
            Other(e) => RedisError::String(format!("{}\n\n {}", e, e.backtrace())),
        }
    }
}

impl<T> From<T> for Error
where
    T: Into<FailError>,
{
    fn from(e: T) -> Self {
        Error::Other(e.into())
    }
}

impl Error {
    fn from(e: RedisError) -> Self {
        Error::Redis(e)
    }
}

// impl From<Result<String, Error>> for RedisResult<RedisValue, RedisError> {}

// load_module takes form of:
// <command> <module name> <module version #> <module bytes> <...module config>
// 1.
// 2.
fn load_module(ctx: &Context, args: Vec<String>) -> Result<String, Error> {
    let name = args.get(0).ok_or(Error::from(RedisError::WrongArity))?;
    let version = args.get(1).ok_or(Error::from(RedisError::WrongArity))?;
    let bytes = args.get(2).ok_or(Error::from(RedisError::WrongArity))?;

    let mut file = Builder::new()
        .prefix("redis-module-shim")
        .suffix("so")
        .rand_bytes(5)
        .tempfile()?;

    println!("b64 len: {}", bytes.len());

    let bytes = base64::decode(bytes)?;
    println!("file bytes: {}", bytes.len());

    file.write(&bytes)?;
    let (file, path) = file.keep()?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;

    let pathstr = path.to_str().unwrap();

    use std::os::unix::fs::PermissionsExt;

    let module: Container<Module> = unsafe { Container::load(pathstr) }.map_err(|e| {
        format_err!(
            "provided module loaded, but it does not appear to be a shimmable redis module:\n\n{}",
            e
        )
    })?;

    ctx.call("MODULE", &["LOAD", pathstr])
        .map_err(|e| format_err!("failed on load module call: {}", e))?;

    Ok(format!("loaded {} {}", module.name(), module.version()))
}

fn dispatch(ctx: &Context, args: Vec<String>) -> RedisResult {
    let args = args.into_iter().skip(1).collect::<Vec<String>>();

    match load_module(ctx, args) {
        Ok(v) => RedisResult::Ok(RedisValue::SimpleString(v)),
        Err(e) => RedisResult::Err(e.into()),
    }
}

//////////////////////////////////////////////////////

redis_module! {
    name: "HOTMOD",
    version: mod_version(),
    data_types: [],
    commands: [
        [mod_name(), dispatch, "", 0, 0, 0],
    ],
}

//////////////////////////////////////////////////////

#[no_mangle]
pub fn mod_name() -> &'static str {
    "HOTMOD"
}

#[no_mangle]
pub fn mod_version() -> u32 {
    1
}

#[no_mangle]
pub static is_mod: bool = true;
