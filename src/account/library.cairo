%lang starknet

const TRANSACTION_VERSION = 1;
// The offset for query transaction versions
const QUERY_VERSION_BASE = 2**128;
// For transactions meant to query and not to be executed by the Starknet OS
const QUERY_VERSION = QUERY_VERSION_BASE + TRANSACTION_VERSION;

struct Call {
    to: felt,
    selector: felt,
    calldata_len: felt,
    calldata: felt*,
}

// Tmp struct introduced while we wait for Cairo
// to support passing `[Call]` to __execute__
struct AccountCallArray {
    to: felt,
    selector: felt,
    data_offset: felt,
    data_len: felt,
}