%lang starknet

from starkware.cairo.common.cairo_builtins import EcOpBuiltin, HashBuiltin, SignatureBuiltin
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.hash_state import (
    HashState,
    hash_finalize,
    hash_init,
    hash_update,
    hash_update_single,
)
from starkware.cairo.common.ec import StarkCurve, ec_add, ec_mul, ec_sub, is_x_on_curve, recover_y
from starkware.cairo.common.ec_point import EcPoint
from starkware.cairo.common.bool import FALSE, TRUE
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math_cmp import is_le_felt
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_not_zero, assert_nn
from starkware.starknet.common.syscalls import (
    call_contract,
    get_tx_info,
    get_contract_address,
    get_caller_address,
    get_block_timestamp,
)

const _SEPARATION_SIG=1;

@contract_interface
namespace IAccount {
    func isValidSignature(hash: felt, sig_len: felt, sig: felt*) {
    }
}

struct CallArray {
    to: felt,
    selector: felt,
    data_offset: felt,
    data_len: felt,
}

///////////////////////
// EVENTS
///////////////////////

@event
func keyAgg_set(account: felt, key: felt) {
}


@storage_var
func Key_agg() -> (res: felt) {
}

@external
func initialize{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    keyAgg: felt
) -> () {
    // check that we are not already initialized
    let (currentAccount_signer) = Key_agg.read();
    with_attr error_message("already initialized") {
        assert currentAccount_signer = 0;
    }
    // check that the target signer is not zero
    with_attr error_message("signer cannot be null") {
        assert_not_zero(keyAgg);
    }
    // initialize the contract
    Key_agg.write(keyAgg);

    // emit event
    let (self) = get_contract_address();
    keyAgg_set.emit(account=self, key=keyAgg);
    return ();
}

@external
func validate{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, ecdsa_ptr: SignatureBuiltin*, range_check_ptr, ec_op_ptr:EcOpBuiltin*
}(
    plugin_data_len: felt,
    plugin_data: felt*,
    call_array_len: felt,
    call_array: CallArray*,
    calldata_len: felt,
    calldata: felt*,
) {
    alloc_locals;

    // get the tx info
    let (tx_info) = get_tx_info();

    let KeyAgg: felt = Key_agg.read();

    // check if the tx is signed by the session key
    with_attr error_message("shnorr signature invalid") {
        let (flag_verif) = Verif_Musig2_all_xonly{hash_ptr=pedersen_ptr, ec_op_ptr2=ec_op_ptr}(
            R=tx_info.signature[0],
            s=tx_info.signature[1],
            KeyAgg=KeyAgg,
            message=tx_info.transaction_hash
        );
        assert flag_verif = TRUE;
    }

    return ();
}

// /** \brief Hsig, hashing function, with x-only convention

// * Implicit:
// * \param[in]  R part of the signatures as x of type felt, y is recovered
// * \param[in]  s part of the signatures  (type: felt)
// * Inputs:
// * \param[in]  R part of the signatures as x of type felt, y is recovered
// * \param[in]  s part of the signatures  (type: felt)
// * \param[in]  X Aggregated key (x,y) as a couple of felt (type: felt*)
// * \param[in]  message, here the transaction hash hence only one felt (type: felt)
// * Output:
// * \param[out] Hsign the value of the hash (type: felt)
// * The Hsig function of [MUSIG2], instanciated with pedersen hash. All data are represented as felt, the 
// * payload input is X|| R|| m, where || notes concatenation
// */
func HSig_xonly{ hash_ptr: HashBuiltin*, ec_op_ptr2: EcOpBuiltin*}(R:felt, s:felt, X :felt, message: felt)->(Hsign:felt){
	// compute c =·= Hsig(X, R, m ),
	alloc_locals;
	let (__fp__, _) = get_fp_and_pc();
	
	let (Hsig: HashState*) = hash_init();
	local const_separation=_SEPARATION_SIG;
	
	let Hsig_0: HashState* =hash_update{hash_ptr=hash_ptr}(Hsig, &const_separation, 1);
	
	let Hsig_X: HashState* =hash_update{hash_ptr=hash_ptr}(Hsig_0, &X, 1);// append Aggregated key to hash
		
	let Hsig_XR: HashState* =hash_update{hash_ptr=hash_ptr}(Hsig_X, &R, 1);// append R part of sig to hash
	let Hsig_XRm: HashState* =hash_update_single{hash_ptr=hash_ptr}(Hsig_XR, message);// append message to hash
	
	let d: felt= hash_finalize{hash_ptr=hash_ptr}(Hsig_XRm);// get hash result as felt
 	return (Hsign=d);
}

// /** \brief The core verification algorithm, computed in one shot (hash internally)

// * Implicit:

// * Inputs:
// * \param[in]  R part of the signatures as x of type felt, y is recovered
// * \param[in]  s part of the signatures  (type: felt)
// * \param[in]  KeyAgg compressed Aggregated key x. y is recovered. (type: felt)
// * \param[in]  message, here the transaction hash hence only one felt (type: felt)
// * Output:
// * \param[out] flag_verif the value of the verification (TRUE/FALSE), encoded as felt
// * The verification function of [MUSIG2], instanciated with pedersen hash over the Starkcurve. 
// */
//
func Verif_Musig2_all_xonly{ hash_ptr: HashBuiltin*, ec_op_ptr2: EcOpBuiltin*}(R:felt, s:felt, KeyAgg :felt, message: felt) ->(flag_verif:felt){
	alloc_locals;
	
	//cy_ecpoint_t *G=cy_ec_get_generator(ctx->ctx_ec); /* get generating point of the curve , todo ec: coder un get_generator */
	let ecpoint_G:EcPoint=EcPoint(x=StarkCurve.GEN_X, y=StarkCurve.GEN_Y);
	//CY_CHECK(cy_ec_scalarmult_fp(ctx->ctx_ec, G, s, &ec_temp1)); 	/*g^s*/
	let g_pow_s: EcPoint = ec_mul{ec_op_ptr=ec_op_ptr2}(s, ecpoint_G);
   	let ecpoint_X: EcPoint = recover_y(KeyAgg);
   	
	// compute c =·= Hsig(X, R, m ),	
	let c: felt= HSig_xonly(R,s,KeyAgg, message);// get hash result as felt

	local d=c;
	
	//let ecpoint_R: EcPoint = EcPoint(x=R[0], y=R[1]);
	
	let ecpoint_R: EcPoint = recover_y(R);
	let ecpoint_X_pow_c:EcPoint=ec_mul{ec_op_ptr=ec_op_ptr2}(d, ecpoint_X);//compute X^c
	let ecpoint_RXc:EcPoint=ec_add(ecpoint_R, ecpoint_X_pow_c);//compute RX^c
		
	//* verifier accepts the signature if gs = RXec*/
	if(  ecpoint_RXc.x == g_pow_s.x){
	   return (flag_verif=TRUE);
	}
	// testing R-Xc for point compression, note that it restores some malleability and should
	let ecpoint_RmXc:EcPoint=ec_sub( ecpoint_X_pow_c, ecpoint_R);//compute RX^c
	if(  ecpoint_RmXc.x == g_pow_s.x){
	   return (flag_verif=TRUE);
	}
	   return (flag_verif=FALSE);
}		