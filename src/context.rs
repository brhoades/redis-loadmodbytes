pub use failure::Error;
pub use redis_module::{RedisError, RedisResult, RedisValue};

pub trait Context {
    fn call<C, A, I>(&self, command: C, args: I) -> Result<RedisValue, Error>
    where
        C: AsRef<str>,
        A: AsRef<str>,
        I: IntoIterator<Item = A>;

    fn replicate_verbatim(&self);
    fn log_warning<T: AsRef<str>>(&self, arg: T);
    fn log_notice<T: AsRef<str>>(&self, arg: T);
    fn log_debug<T: AsRef<str>>(&self, arg: T);
}

impl Context for redis_module::Context {
    fn call<C, A, I>(&self, command: C, args: I) -> Result<RedisValue, Error>
    where
        C: AsRef<str>,
        A: AsRef<str>,
        I: IntoIterator<Item = A>,
    {
        let args = args.into_iter().collect::<Vec<_>>();
        let result = self.call(
            command.as_ref(),
            args.iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        match result {
            RedisResult::Ok(v) => Ok(v),
            RedisResult::Err(e) => Err(format_err!("error on {}: {}", command.as_ref(), e)),
        }
    }

    fn replicate_verbatim(&self) {
        self.replicate_verbatim()
    }

    fn log_warning<T: AsRef<str>>(&self, arg: T) {
        self.log_warning(arg.as_ref())
    }

    fn log_debug<T: AsRef<str>>(&self, arg: T) {
        self.log_debug(arg.as_ref())
    }

    fn log_notice<T: AsRef<str>>(&self, arg: T) {
        self.log_notice(arg.as_ref())
    }
}
