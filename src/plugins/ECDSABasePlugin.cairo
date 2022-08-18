%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_not_zero
from starkware.starknet.common.syscalls import (
    get_tx_info, get_contract_address, get_caller_address
)

from starkware.cairo.common.bool import TRUE, FALSE
from openzeppelin.introspection.erc165.library import ERC165
from openzeppelin.utils.constants.library import IACCOUNT_ID

struct AccountCallArray:
    member to: felt
    member selector: felt
    member data_offset: felt
    member data_len: felt
end

####################
# CONSTANTS
####################

####################
# EVENTS
####################

@event
func account_created(account: felt, key: felt):
end

####################
# STORAGE VARIABLES
####################

@storage_var
func Account_public_key() -> (res: felt):
end

####################
# PLUGIN INTERFACE
####################

@external
func validate{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        plugin_data_len: felt,
        plugin_data: felt*,
        call_array_len: felt,
        call_array: AccountCallArray*,
        calldata_len: felt,
        calldata: felt*
    ):
    alloc_locals

    # make sure the account is initialized
    assert_initialized()
    
    # get the tx info
    let (tx_info) = get_tx_info()

    is_valid_signature(tx_info.transaction_hash, tx_info.signature_len, tx_info.signature)
    return()
end

####################
# EXTERNAL FUNCTIONS
####################

@external
func initialize{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        plugin_data_len: felt,
        plugin_data: felt*
    ) -> ():
    let signer = [plugin_data]
    # check that we are not already initialized
    let (currentAccount_signer) = Account_public_key.read()
    with_attr error_message("already initialized"):
        assert currentAccount_signer = 0
    end
    # check that the target signer is not zero
    with_attr error_message("signer cannot be null"):
        assert_not_zero(signer)
    end
    # initialize the contract
    Account_public_key.write(signer)
    ERC165.register_interface(IACCOUNT_ID)

    # emit event
    let (self) = get_contract_address()
    account_created.emit(account=self, key=signer)
    return ()
end

####################
# SETTERS
####################

@external
func set_public_key{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(
        new_public_key: felt
    ):
    assert_only_self()
    Account_public_key.write(new_public_key)
    return ()
end

####################
# VIEW FUNCTIONS
####################

@view
func is_valid_signature{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*
    }(
        hash: felt,
        signature_len: felt,
        signature: felt*
    ) -> (is_valid: felt):
    let (_public_key) = Account_public_key.read()

    # This interface expects a signature pointer and length to make
    # no assumption about signature validation schemes.
    # But this implementation does, and it expects a (sig_r, sig_s) pair.
    let sig_r = signature[0]
    let sig_s = signature[1]

    verify_ecdsa_signature(
        message=hash,
        public_key=_public_key,
        signature_r=sig_r,
        signature_s=sig_s)

    return (is_valid=TRUE)
end


@view
func get_signer{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } () -> (signer: felt):
    let (res) = Account_public_key.read()
    return (signer=res)
end

####################
# INTERNAL FUNCTIONS
####################

func assert_initialized{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } ():
    let (signer) = Account_public_key.read()
    with_attr error_message("account not initialized"):
        assert_not_zero(signer)
    end
    return()
end

func assert_only_self{
        syscall_ptr: felt*
    } () -> ():
    let (self) = get_contract_address()
    let (caller_address) = get_caller_address()
    with_attr error_message("must be called via execute"):
        assert self = caller_address
    end
    return()
end