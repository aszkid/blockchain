
pub trait Method: Send + Sync {
    fn name(&self) -> &'static str;
}

pub struct DumpPrivKey;

impl Method for DumpPrivKey {
    fn name(&self) -> &'static str { "dumpprivkey" }
}

