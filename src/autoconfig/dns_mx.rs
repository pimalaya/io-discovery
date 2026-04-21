use domain::base::{
    Message, MessageBuilder, Name, Rtype, StreamTarget,
};
use thiserror::Error;

/// Errors that can occur during a DNS TCP query.
#[derive(Debug, Error)]
pub enum DnsMxError {
    #[error("DNS MX reached unexpected EOF")]
    Eof,
}

/// Output emitted when the coroutine terminates its progression.
pub enum DnsMxResult<'a> {
    /// The coroutine has successfully decoded a DNS response.
    Ok(&'a Message<[u8]>),
    /// A socket I/O needs to be performed to make the coroutine progress.
    WantsRead,
    WantsWrite(StreamTarget<Vec<u8>>),
    /// An error occurred during the coroutine progression.
    Err(DnsMxError),
}

#[derive(Debug)]
pub struct DnsMx {
    wants_read: bool,
    wants_write: Option<StreamTarget<Vec<u8>>>,
}

impl DnsMx {
    /// Creates a new coroutine that will query `name` for `qtype` records
    /// over TCP, using the given message `id`.
    pub fn new(domain: &str) -> Self {
        let target = StreamTarget::new_vec();
        let mut msg = MessageBuilder::from_target(target).unwrap();

        msg.header_mut().set_id(0x0001);

        let mut msg = msg.question();

        // Add a hard-coded question and proceed to the answer section.
        msg.push((Name::vec_from_str(domain).unwrap(), Rtype::MX))
            .unwrap();

        // Skip to the additional section
        let mut msg = msg.additional();

        // Add an OPT record.
        msg.opt(|opt| {
            opt.set_udp_payload_size(4096);
            Ok(())
        })
        .unwrap();

        Self {
            wants_read: false,
            wants_write: Some(msg.finish()),
        }
    }

    /// Makes the coroutine progress.
    pub fn resume<'a>(&mut self, arg: &'a [u8]) -> DnsMxResult<'a> {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                self.wants_read = true;
                return DnsMxResult::WantsWrite(bytes);
            }

            if self.wants_read {
                self.wants_read = false;
                return DnsMxResult::WantsRead;
            }

            return match Message::from_slice(arg) {
                Ok(msg) => DnsMxResult::Ok(msg),
                Err(_) if arg.is_empty() => DnsMxResult::Err(DnsMxError::Eof),
                Err(_) => {
                    // SAFETY: the only error possible is
                    // ShortMessage, which means we need to read more
                    self.wants_read = true;
                    continue;
                }
            };
        }
    }
}
