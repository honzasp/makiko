use std::ops::{BitOr, BitOrAssign};

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

impl BitOr<Pump> for Pump {
    type Output = Pump;
    fn bitor(self, rhs: Pump) -> Pump {
        match (self, rhs) {
            (Pump::Progress, _) => Pump::Progress,
            (_, Pump::Progress) => Pump::Progress,
            (Pump::Pending, Pump::Pending) => Pump::Pending,
        }
    }
}

impl BitOrAssign<Pump> for Pump {
    fn bitor_assign(&mut self, rhs: Pump) {
        *self = *self | rhs;
    }
}
