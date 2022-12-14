%lang starknet

from src.account.library import AccountCallArray

@contract_interface
namespace IPluginAccount {

    /////////////////////
    // Plugin
    /////////////////////

    func addPlugin(plugin: felt, plugin_calldata_len: felt, plugin_calldata: felt*) {
    }

    func removePlugin(plugin: felt) {
    }

    func setDefaultPlugin(plugin: felt) {
    }

    func isPlugin(plugin: felt) -> (success: felt) {
    }

    func readOnPlugin(plugin: felt, selector: felt, calldata_len: felt, calldata: felt*) {
    }

    func getDefaultPlugin() -> (plugin: felt) {
    }

    /////////////////////
    // IAccount
    /////////////////////

    func supportsInterface(interfaceId: felt) -> (success: felt) {
    }

    func isValidSignature(hash: felt, signature_len: felt, signature: felt*) -> (isValid: felt) {
    }

    func __validate__(
        call_array_len: felt,
        call_array: AccountCallArray*,
        calldata_len: felt,
        calldata: felt*
    ) {
    }

    // Parameter temporarily named `cls_hash` instead of `class_hash` (expected).
    // See https://github.com/starkware-libs/cairo-lang/issues/100 for details.
    func __validate_declare__(class_hash: felt) {
    }

    // Parameter temporarily named `cls_hash` instead of `class_hash` (expected).
    // See https://github.com/starkware-libs/cairo-lang/issues/100 for details.
    func __validate_deploy__(
        cls_hash: felt, ctr_args_len: felt, ctr_args: felt*, salt: felt
    ) {
    }

    func __execute__(
        call_array_len: felt,
        call_array: AccountCallArray*,
        calldata_len: felt,
        calldata: felt*
    ) -> (response_len: felt, response: felt*) {
    }
}
