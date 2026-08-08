use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::domain::resp::{ExecError, RespValue};
use crate::ports::{CommandExecutor, RedisCommand};

pub struct FakeExecutor {
    replies: Mutex<VecDeque<Result<RespValue, ExecError>>>,
    calls: Mutex<Vec<Vec<RedisCommand>>>,
}

impl FakeExecutor {
    pub fn new(replies: impl IntoIterator<Item = Result<RespValue, ExecError>>) -> Self {
        Self {
            replies: Mutex::new(replies.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> Vec<Vec<RedisCommand>> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn record(&self, commands: Vec<RedisCommand>) {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(commands);
    }

    fn next(&self) -> Result<RespValue, ExecError> {
        self.replies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front()
            .unwrap_or_else(|| {
                Err(ExecError::Transport(
                    "FakeExecutor reply script exhausted".to_owned(),
                ))
            })
    }
}

#[async_trait]
impl CommandExecutor for FakeExecutor {
    async fn execute(&self, command: RedisCommand) -> Result<RespValue, ExecError> {
        self.record(vec![command]);
        self.next()
    }

    async fn pipeline(&self, commands: Vec<RedisCommand>) -> Vec<Result<RespValue, ExecError>> {
        let count = commands.len();
        self.record(commands);
        (0..count).map(|_| self.next()).collect()
    }

    async fn transaction(&self, commands: Vec<RedisCommand>) -> Result<Vec<RespValue>, ExecError> {
        let count = commands.len();
        self.record(commands);
        (0..count).map(|_| self.next()).collect()
    }
}
