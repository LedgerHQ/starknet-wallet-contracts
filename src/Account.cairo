%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.math import assert_not_zero, assert_nn
from starkware.starknet.common.syscalls import (
    library_call,
    call_contract,
    get_tx_info,
    get_contract_address,
    get_caller_address,
)
from starkware.cairo.common.bool import TRUE, FALSE

from openzeppelin.introspection.erc165.library import ERC165
from openzeppelin.utils.constants.library import IACCOUNT_ID

@contract_interface
namespace IPlugin {
    // Method to call during validation
    func validate(
        plugin_data_len: felt,
        plugin_data: felt*,
        call_array_len: felt,
        call_array: AccountCallArray*,
        calldata_len: felt,
        calldata: felt*,
    ) {
    }
}

//###################
// CONSTANTS
//###################

const VERSION = '0.1.0';
const USE_PLUGIN_SELECTOR = 1121675007639292412441492001821602921366030142137563176027248191276862353634;

//###################
// STRUCTS
//###################

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

//###################
// EVENTS
//###################

@event
func signer_changed(newAccount_signer: felt) {
}

@event
func account_created(account: felt, key: felt) {
}

@event
func transaction_executed(hash: felt, response_len: felt, response: felt*) {
}

//###################
// STORAGE VARIABLES
//###################

@storage_var
func Account_public_key() -> (res: felt) {
}

@storage_var
func Account_plugins(plugin: felt) -> (res: felt) {
}

//###################
// EXTERNAL FUNCTIONS
//###################

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(signer: felt) {
    // check that we are not already initialized
    let (currentAccount_signer) = Account_public_key.read();
    with_attr error_message("already initialized") {
        assert currentAccount_signer = 0;
    }
    // check that the target signer is not zero
    with_attr error_message("signer cannot be null") {
        assert_not_zero(signer);
    }
    // initialize the contract
    Account_public_key.write(signer);
    ERC165.register_interface(IACCOUNT_ID);

    // emit event
    let (self) = get_contract_address();
    account_created.emit(account=self, key=signer);
    return ();
}

@external
@raw_output
func __execute__{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, ecdsa_ptr: SignatureBuiltin*, range_check_ptr
}(
    call_array_len: felt,
    call_array: AccountCallArray*,
    calldata_len: felt,
    calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    alloc_locals;

    // validate calls
    // validate(call_array_len, call_array, calldata_len, calldata, nonce);

    let (caller) = get_caller_address();
    with_attr error_message("Account: no reentrant call") {
        assert caller = 0;
    }

    // TMP: Convert `AccountCallArray` to 'Call'.
    let (calls: Call*) = alloc();
    _from_call_array_to_call(call_array_len, call_array, calldata, calls);
    let calls_len = call_array_len;

    // execute calls
    let (response: felt*) = alloc();
    local response_len;
    if (calls[0].selector - USE_PLUGIN_SELECTOR == 0) {
        let (res) = _execute_list(calls_len - 1, calls + Call.SIZE, response);
        assert response_len = res;
    } else {
        let (res) = _execute_list(calls_len, calls, response);
        assert response_len = res;
    }

    // emit event
    let (tx_info) = get_tx_info();
    transaction_executed.emit(
        hash=tx_info.transaction_hash, response_len=response_len, response=response
    );

    return (retdata_size=response_len, retdata=response);
}

@external
func __validate__{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, ecdsa_ptr: SignatureBuiltin*, range_check_ptr
}(
    call_array_len: felt,
    call_array: AccountCallArray*,
    calldata_len: felt,
    calldata: felt*
) {
    alloc_locals;

    // make sure the account is initialized
    assert_initialized();

    let (tx_info) = get_tx_info();

    if ((call_array[0].to - tx_info.account_contract_address) + (call_array[0].selector - USE_PLUGIN_SELECTOR) == 0) {
        validate_with_plugin(call_array_len, call_array, calldata_len, calldata);
        return ();
    }

    // validate transaction
    with_attr error_message("Account: invalid secp256k1 signature") {
        let (is_valid) = is_valid_signature(
            tx_info.transaction_hash, tx_info.signature_len, tx_info.signature
        );
        assert is_valid = TRUE;
    }

    return ();
}

@external
func __validate_declare__{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
    range_check_ptr
} (
    class_hash: felt
) {
    alloc_locals;
    // get the tx info
    let (tx_info) = get_tx_info();
    is_valid_signature(tx_info.transaction_hash, tx_info.signature_len, tx_info.signature);
    return ();
}


@external
func set_public_key{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    new_public_key: felt
) {
    assert_only_self();
    Account_public_key.write(new_public_key);
    return ();
}

// ##### PLUGIN #######

@external
func add_plugin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(plugin: felt) {
    // only called via execute
    assert_only_self();

    // add plugin
    with_attr error_message("plugin cannot be null") {
        assert_not_zero(plugin);
    }
    Account_plugins.write(plugin, 1);
    return ();
}

@external
func remove_plugin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(plugin: felt) {
    // only called via execute
    assert_only_self();
    // remove plugin
    Account_plugins.write(plugin, 0);
    return ();
}

@external
func execute_on_plugin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    plugin: felt, selector: felt, calldata_len: felt, calldata: felt*
) {
    // only called via execute
    assert_only_self();
    // only valid plugin
    let (is_plugin) = Account_plugins.read(plugin);
    assert_not_zero(is_plugin);

    library_call(
        class_hash=plugin, function_selector=selector, calldata_size=calldata_len, calldata=calldata
    );
    return ();
}

@view
func is_plugin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(plugin: felt) -> (
    success: felt
) {
    let (res) = Account_plugins.read(plugin);
    return (success=res);
}

func validate_with_plugin{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, ecdsa_ptr: SignatureBuiltin*, range_check_ptr
}(call_array_len: felt, call_array: AccountCallArray*, calldata_len: felt, calldata: felt*) {
    alloc_locals;

    let plugin = calldata[call_array[0].data_offset];
    let (is_plugin) = Account_plugins.read(plugin);
    assert_not_zero(is_plugin);

    IPlugin.library_call_validate(
        class_hash=plugin,
        plugin_data_len=call_array[0].data_len - 1,
        plugin_data=calldata + call_array[0].data_offset + 1,
        call_array_len=call_array_len - 1,
        call_array=call_array + AccountCallArray.SIZE,
        calldata_len=calldata_len - call_array[0].data_len,
        calldata=calldata + call_array[0].data_offset + call_array[0].data_len,
    );
    return ();
}

//###################
// VIEW FUNCTIONS
//###################

@view
func is_valid_signature{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, ecdsa_ptr: SignatureBuiltin*
}(hash: felt, signature_len: felt, signature: felt*) -> (is_valid: felt) {
    let (_public_key) = Account_public_key.read();

    // This interface expects a signature pointer and length to make
    // no assumption about signature validation schemes.
    // But this implementation does, and it expects a (sig_r, sig_s) pair.
    let sig_r = signature[0];
    let sig_s = signature[1];

    verify_ecdsa_signature(
        message=hash, public_key=_public_key, signature_r=sig_r, signature_s=sig_s
    );

    return (is_valid=TRUE);
}

@view
func get_public_key{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    let (res) = Account_public_key.read();
    return (res=res);
}

@view
func supportsInterface{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    interfaceId: felt
) -> (success: felt) {
    let (success) = ERC165.supports_interface(interfaceId);
    return (success,);
}

@view
func get_version() -> (version: felt) {
    return (version=VERSION);
}

//###################
// INTERNAL FUNCTIONS
//###################

func assert_only_self{syscall_ptr: felt*}() -> () {
    let (self) = get_contract_address();
    let (caller_address) = get_caller_address();
    with_attr error_message("Account: caller is not this account") {
        assert self = caller_address;
    }
    return ();
}

func assert_initialized{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    let (signer) = Account_public_key.read();
    with_attr error_message("Account: not initialized") {
        assert_not_zero(signer);
    }
    return ();
}

func _execute_list{syscall_ptr: felt*}(calls_len: felt, calls: Call*, reponse: felt*) -> (
    response_len: felt
) {
    alloc_locals;

    // if no more calls
    if (calls_len == 0) {
        return (0,);
    }

    // do the current call
    let this_call: Call = [calls];
    let res = call_contract(
        contract_address=this_call.to,
        function_selector=this_call.selector,
        calldata_size=this_call.calldata_len,
        calldata=this_call.calldata,
    );
    // copy the result in response
    memcpy(reponse, res.retdata, res.retdata_size);
    // do the next calls recursively
    let (response_len) = _execute_list(
        calls_len - 1, calls + Call.SIZE, reponse + res.retdata_size
    );
    return (response_len + res.retdata_size,);
}

func _from_call_array_to_call{syscall_ptr: felt*}(
    call_array_len: felt, call_array: AccountCallArray*, calldata: felt*, calls: Call*
) {
    // if no more calls
    if (call_array_len == 0) {
        return ();
    }

    // parse the current call
    assert [calls] = Call(
        to=[call_array].to,
        selector=[call_array].selector,
        calldata_len=[call_array].data_len,
        calldata=calldata + [call_array].data_offset
        );

    // parse the remaining calls recursively
    _from_call_array_to_call(
        call_array_len - 1, call_array + AccountCallArray.SIZE, calldata, calls + Call.SIZE
    );
    return ();
}
