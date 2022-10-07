%lang starknet

from src.account.library import AccountCallArray

@contract_interface
namespace IPlugin {

    func initialize(data_len: felt, data: felt*) {
    }

    func validate(
        call_array_len: felt,
        call_array: AccountCallArray*,
        calldata_len: felt,
        calldata: felt*,
    ) {
    }
}
