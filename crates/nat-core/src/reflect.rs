use packet::l4::{ACK, FIN, RST, SYN};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    SynSent,
    Established,
    Closing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    Out,
    In,
}

// Moved a flow's TCP state along, or said no when an outsider tried to start or revive one.
pub fn step(state: TcpState, dir: Dir, flags: u8) -> Option<TcpState> {
    if flags & (RST | FIN) != 0 {
        return Some(TcpState::Closing);
    }
    match (state, dir) {
        (TcpState::SynSent, Dir::In) if flags & (SYN | ACK) == SYN | ACK => Some(TcpState::Established),
        (TcpState::Established | TcpState::Closing, Dir::In) if flags & SYN != 0 => None,
        (_, Dir::In) if state == TcpState::SynSent => None,
        (TcpState::Closing, Dir::Out) if flags & (SYN | ACK) == SYN => Some(TcpState::SynSent),
        _ => Some(state),
    }
}
