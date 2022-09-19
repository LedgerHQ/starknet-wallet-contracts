%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.math import assert_not_zero, assert_nn
from starkware.cairo.common.math_cmp import is_not_zero
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

    // Method to write data during Init (delegate call)
    func initialize(plugin_data_len: felt, plugin_data: felt*) {
    }

    // delegate this call to the default plugin
    // this ocntract does not know its signer or signature scheme
    func isValidSignature(hash: felt, signature_len: felt, signature: felt*) -> (is_valid: felt) {
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
func transaction_executed(hash: felt, response_len: felt, response: felt*) {
}

//###################
// STORAGE VARIABLES
//###################

@storage_var
func Account_current_plugin() -> (res: felt) {
}

@storage_var
func Account_default_plugin() -> (res: felt) {
}

@storage_var
func Account_plugins(plugin: felt) -> (res: felt) {
}

//###################
// EXTERNAL FUNCTIONS
//###################

@external
func initialize{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    plugin_id: felt, plugin_data_len: felt, plugin_data: felt*
) {
    alloc_locals;

    // check that we are not already initialized
    let (current_plugin) = Account_default_plugin.read();
    with_attr error_message("already initialized") {
        assert current_plugin = 0;
    }
    // check that the target signer is not zero
    with_attr error_message("signer cannot be null") {
        assert_not_zero(plugin_id);
    }

    // initialize the default plugin
    IPlugin.library_call_initialize(
        class_hash=plugin_id, plugin_data_len=plugin_data_len, plugin_data=plugin_data
    );

    Account_default_plugin.write(plugin_id);
    Account_plugins.write(plugin_id, 1);
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

    let (is_plugin, plugin_id, plugin_data_len, plugin_data) = usePlugin(
        call_array_len, call_array, calldata_len, calldata
    );
    let (tx_info) = get_tx_info();

    if (is_plugin == TRUE) {
        Account_current_plugin.write(plugin_id);
        validate_with_plugin(
            plugin_id,
            plugin_data_len,
            plugin_data,
            call_array_len - 1,
            call_array + AccountCallArray.SIZE,
            calldata_len,
            calldata,
        );
        return ();
    }

    // validate transaction with default plugin
    let (default_plugin) = Account_default_plugin.read();
    validate_with_plugin(
        default_plugin, 0, plugin_data, call_array_len, call_array, calldata_len, calldata
    );

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
    isValidSignature(tx_info.transaction_hash, tx_info.signature_len, tx_info.signature);
    return ();
}

// ##### PLUGIN #######

@external
func addPlugin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(plugin: felt) {
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
func removePlugin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(plugin: felt) {
    // only called via execute
    assert_only_self();
    // remove plugin
    Account_plugins.write(plugin, 0);
    return ();
}

@external
func executeOnPlugin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
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
func isPlugin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(plugin: felt) -> (
    success: felt
) {
    let (res) = Account_plugins.read(plugin);
    return (success=res);
}

func validate_with_plugin{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, ecdsa_ptr: SignatureBuiltin*, range_check_ptr
}(
    plugin_id: felt,
    plugin_data_len: felt,
    plugin_data: felt*,
    call_array_len: felt,
    call_array: AccountCallArray*,
    calldata_len: felt,
    calldata: felt*,
) {
    alloc_locals;

    IPlugin.library_call_validate(
        class_hash=plugin_id,
        plugin_data_len=plugin_data_len,
        plugin_data=plugin_data,
        call_array_len=call_array_len,
        call_array=call_array,
        calldata_len=calldata_len,
        calldata=calldata,
    );
    return ();
}

func usePlugin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    call_array_len: felt, call_array: AccountCallArray*, calldata_len: felt, calldata: felt*
) -> (is_plugin: felt, plugin_id: felt, plugin_data_len: felt, plugin_data: felt*) {
    alloc_locals;

    let (plugin_data: felt*) = alloc();
    let res = is_not_zero(call_array[0].selector - USE_PLUGIN_SELECTOR);
    if (res == 1) {
        return (is_plugin=FALSE, plugin_id=0, plugin_data_len=0, plugin_data=plugin_data);
    }
    let plugin_id = calldata[call_array[0].data_offset];
    // should this assert???
    let (is_plugin) = Account_plugins.read(plugin_id);
    memcpy(plugin_data, calldata + call_array[0].data_offset + 1, call_array[0].data_len - 1);
    return (
        is_plugin=is_plugin,
        plugin_id=plugin_id,
        plugin_data_len=call_array[0].data_len - 1,
        plugin_data=plugin_data,
    );
}

//###################
// VIEW FUNCTIONS
//###################

@view
func isValidSignature{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, ecdsa_ptr: SignatureBuiltin*
}(hash: felt, signature_len: felt, signature: felt*) -> (is_valid: felt) {
    alloc_locals;

    let (default_plugin) = Account_default_plugin.read();

    IPlugin.library_call_isValidSignature(
        class_hash=default_plugin, hash=hash, signature_len=signature_len, signature=signature
    );

    return (is_valid=TRUE);
}

@view
func readOnPlugin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    plugin: felt, selector: felt, calldata_len: felt, calldata: felt*
) -> (retdata_len: felt, retdata: felt*) {
    // only valid plugin
    let (is_plugin) = Account_plugins.read(plugin);
    assert_not_zero(is_plugin);

    let (retdata_len, retdata) = library_call(
        class_hash=plugin, function_selector=selector, calldata_size=calldata_len, calldata=calldata
    );
    return (retdata_len=retdata_len, retdata=retdata);
}

@view
func supportsInterface{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    interfaceId: felt
) -> (success: felt) {
    let (success) = ERC165.supports_interface(interfaceId);
    return (success,);
}

@view
func getVersion() -> (version: felt) {
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
    let (signer) = Account_default_plugin.read();
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
