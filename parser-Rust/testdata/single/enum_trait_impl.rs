pub enum Status {
    Ready,
    Busy = 2,
}

pub trait Worker: Send {
    fn id(&self) -> i32;
    fn run(&self) -> i32 {
        1
    }
}

pub struct Agent;

impl Worker for Agent {
    fn id(&self) -> i32 {
        7
    }
}
