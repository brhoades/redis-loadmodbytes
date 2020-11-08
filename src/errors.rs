pub use failure::Error as FailureError;
pub use redis_module::RedisError;

pub enum Error {
    Redis(RedisError),
    Other(FailureError),
}

impl From<Error> for RedisError {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            Redis(e) => e,
            Other(e) => {
                let bt = e.backtrace();
                let mut summary: String = e.to_string();

                if !bt.is_empty() {
                    summary += &("\n\n".to_string() + &bt.to_string())
                }
                RedisError::String(summary)
            }
        }
    }
}

impl<T> From<T> for Error
where
    T: Into<FailureError>,
{
    fn from(e: T) -> Self {
        Error::Other(e.into())
    }
}

impl Error {
    #[allow(dead_code)]
    pub fn from(e: RedisError) -> Self {
        Error::Redis(e)
    }

    pub fn wrong_arity() -> Self {
        Error::Redis(RedisError::WrongArity)
    }
}
