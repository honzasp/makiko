macro_rules! pump_ready {
    ($e:expr) => {
        match $e {
            ::std::task::Poll::Ready(x) => x,
            ::std::task::Poll::Pending => return ::std::result::Result::Ok(Pump::Pending),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Pump {
    Progress,
    Pending,
}

impl Pump {
    pub fn is_progress(self) -> bool {
        match self {
            Pump::Progress => true,
            Pump::Pending => false,
        }
    }
}
