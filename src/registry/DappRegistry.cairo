%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.hash_state import (
    HashState,
    hash_finalize,
    hash_init,
    hash_update,
    hash_update_single,
)
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math_cmp import is_le_felt
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.math import assert_not_zero, assert_nn
from starkware.starknet.common.syscalls import (
    call_contract,
    get_tx_info,
    get_contract_address,
    get_caller_address,
    get_block_timestamp,
)

// H('Session(key:felt,expires:felt,root:merkletree)')
const AUTHORISATION_TYPE_HASH = 0x1aa0e1c56b45cf06a54534fa1707c54e520b842feb21d03b7deddb6f1e340c;


/////////////////////
// EVENTS
/////////////////////

/////////////////////
// STORAGE VARIABLES
/////////////////////


// owners for each registry id
@storage_var
func Registry_owners(id: felt) -> (owner: felt) {
}

// hash(registry_id, addr) -> bool
@storage_var
func Registry_dapp(id_addr: felt) -> (res: felt) {
}

// hash(registry_id, addr, plugin_id) -> bool
@storage_var
func Registry_authorisations(id_addr_plugin: felt) -> (res: felt) {
}


/////////////////////
// EXTERNAL FUNCTIONS
/////////////////////


@external
func createRegistry{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    registry_id: felt, registry_owner: felt
) {
    Registry_owners.write(registry_id, registry_owner);
    return ();
}

@external
func addDapp{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    registry_id: felt, dapp_address: felt
) {
    alloc_locals;
    let (id) = hash2{hash_ptr=pedersen_ptr}(registry_id, dapp_address);
    Registry_dapp.write(id, TRUE);
    return ();
}

@external
func toggleRegistry{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        registry_id: felt, dapp_address: felt, plugin_id: felt
) -> (isValid: felt){
    alloc_locals;
    let (tx_info) = get_tx_info();

    let hash_ptr = pedersen_ptr;
    with hash_ptr {
        let (id) = hash_message(registry_id, tx_info.account_contract_address, dapp_address, plugin_id);
        let pedersen_ptr = hash_ptr;
    }   
    Registry_authorisations.write(id, TRUE);
    let isValid = TRUE;
    return (isValid=isValid);
}

@external
func checkAuthorisation{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        registry_id: felt, account_contract_address: felt, dapp_address: felt, plugin_id: felt
) -> (isValid: felt){
    alloc_locals;

    let hash_ptr = pedersen_ptr;
    with hash_ptr {
        let (id) = hash_message(registry_id, account_contract_address, dapp_address, plugin_id);
        let pedersen_ptr = hash_ptr;
    }
    let (isValid) = Registry_authorisations.read(id);
    return (isValid=isValid);
}


/////////////////////
// INTERNAL FUNCTIONS
/////////////////////

func hash_message{hash_ptr: HashBuiltin*}(
    registry_id: felt, account_contract_address:felt, dapp_address: felt, plugin_id: felt
) -> (
    hash: felt
) {
    let (hash_state) = hash_init();
    let (hash_state) = hash_update_single(hash_state_ptr=hash_state, item=AUTHORISATION_TYPE_HASH);
    let (hash_state) = hash_update_single(hash_state_ptr=hash_state, item=registry_id);
    let (hash_state) = hash_update_single(hash_state_ptr=hash_state, item=account_contract_address);
    let (hash_state) = hash_update_single(hash_state_ptr=hash_state, item=dapp_address);
    let (hash_state) = hash_update_single(hash_state_ptr=hash_state, item=plugin_id);
    let (hash) = hash_finalize(hash_state_ptr=hash_state);
    return (hash=hash);
}
