
pub trait Task {
    fn name() -> String;
    fn args() -> 
}


pub struct DumpPrivKey;

impl Task for DumpPrivKey {
    fn name() -> String { "dumpprivkey" };
}

/// RPC-to-Node communication protocol.
pub enum Task {
    /// Input: none.
    /// Output: <private key, base58-encoded>
    DumpPrivKey,
    /// Input: none.
    /// Output: object.
    ///     num_nodes: Integer
    ///     ...
    GetNetworkInfo,
    /// Input: none.
    /// Output: array of objects.
    ///     id: Integer
    ///     addr: String
    ///     conntime: Integer
    GetPeerInfo
}
