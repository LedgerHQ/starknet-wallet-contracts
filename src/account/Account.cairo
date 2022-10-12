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
from src.plugins.IPlugin import IPlugin
from src.account.library import AccountCallArray, Call, TRANSACTION_VERSION, QUERY_VERSION

/////////////////////
// CONSTANTS
/////////////////////

const VERSION = '0.1.0';
const USE_PLUGIN_SELECTOR = 1121675007639292412441492001821602921366030142137563176027248191276862353634;
const IS_VALID_SIGNATURE_SELECTOR = 939740983698321109974372403944035053902509983902899284679678367046923648926;
const INITIALIZE_SELECTOR = 215307247182100370520050591091822763712463273430149262739280891880522753123;

/////////////////////
// EVENTS
/////////////////////

@event
func account_created(account: felt) {
}

@event
func transaction_executed(hash: felt, response_len: felt, response: felt*) {
}

/////////////////////
// STORAGE VARIABLES
/////////////////////

@storage_var
func Account_current_plugin() -> (res: felt) {
}

@storage_var
func Account_plugins(plugin: felt) -> (res: felt) {
}

/////////////////////
// EXTERNAL FUNCTIONS
/////////////////////

@external
func initialize{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    plugin_id: felt, plugin_calldata_len: felt, plugin_calldata: felt*
) {
    alloc_locals;

    // check that we are not already initialized
    let (is_initialized) = Account_plugins.read(0);
    with_attr error_message("already initialized") {
        assert is_initialized = 0;
    }
    // check that the target signer is not zero
    with_attr error_message("signer cannot be null") {
        assert_not_zero(plugin_id);
    }

    if (plugin_calldata_len == 0) {
        return ();
    }

    // plugin_id 0 is default plugin
    Account_plugins.write(0, plugin_id);
    Account_plugins.write(plugin_id, 1);

    ERC165.register_interface(IACCOUNT_ID);

    let (self) = get_contract_address();
    account_created.emit(self);

    library_call(
        class_hash=plugin_id,
        function_selector=INITIALIZE_SELECTOR,
        calldata_size=plugin_calldata_len,
        calldata=plugin_calldata,
    );

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
    with_attr error_message("Account: Reentrant call") {
        assert caller = 0;
    }

    let (tx_info) = get_tx_info();

    // block transaction with version != 1 or QUERY
    assert_correct_tx_version(tx_info.version);

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

    let (plugin_id) = use_plugin();
    validate_with_plugin(
        plugin_id, call_array_len, call_array, calldata_len, calldata
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

func validate_with_plugin{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, ecdsa_ptr: SignatureBuiltin*, range_check_ptr
}(
    plugin_id: felt,
    call_array_len: felt,
    call_array: AccountCallArray*,
    calldata_len: felt,
    calldata: felt*,
) {
    alloc_locals;

    IPlugin.library_call_validate(
        class_hash=plugin_id,
        call_array_len=call_array_len,
        call_array=call_array,
        calldata_len=calldata_len,
        calldata=calldata,
    );
    return ();
}

/////////////////////
// VIEW FUNCTIONS
/////////////////////

@view
func isValidSignature{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, ecdsa_ptr: SignatureBuiltin*, range_check_ptr
}(hash: felt, sig_len: felt, sig: felt*) -> (isValid: felt) {
    alloc_locals;
    let (default_plugin) = Account_plugins.read(0);

    let (calldata: felt*) = alloc();
    assert calldata[0] = hash;
    assert calldata[1] = sig_len;
    memcpy(calldata + 2, sig, sig_len);

    let (retdata_size: felt, retdata: felt*) = library_call(
        class_hash=default_plugin,
        function_selector=IS_VALID_SIGNATURE_SELECTOR,
        calldata_size=2 + sig_len,
        calldata=calldata,
    );

    assert retdata_size = 1;
    return (isValid=retdata[0]);
}

@view
func isPlugin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(plugin: felt) -> (
    success: felt
) {
    let (res) = Account_plugins.read(plugin);
    return (success=res);
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

/////////////////////
// INTERNAL FUNCTIONS
/////////////////////

func use_plugin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (plugin_id: felt) {
    alloc_locals;

    let (tx_info) = get_tx_info();
    let plugin_id = tx_info.signature[0];
    let (is_plugin) = Account_plugins.read(plugin_id);

    if (is_plugin == TRUE) {
        return (plugin_id=plugin_id);
    } else {
        let (default_plugin) = Account_plugins.read(0);
        return (plugin_id=default_plugin);
    }
}

func assert_only_self{syscall_ptr: felt*}() -> () {
    let (self) = get_contract_address();
    let (caller_address) = get_caller_address();
    with_attr error_message("Account: caller is not this account") {
        assert self = caller_address;
    }
    return ();
}

func assert_initialized{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    let (signer) = Account_plugins.read(0);
    with_attr error_message("Account: not initialized") {
        assert_not_zero(signer);
    }
    return ();
}

func assert_correct_tx_version{syscall_ptr: felt*}(tx_version: felt) -> () {
    with_attr error_message("argent: invalid tx version") {
        assert (tx_version - TRANSACTION_VERSION) * (tx_version - QUERY_VERSION) = 0;
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
